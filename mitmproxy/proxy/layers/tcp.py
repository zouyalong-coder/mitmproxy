"""
TCP 原始转发 layer。

本模块负责在没有更高层协议解析时转发 TCP 字节流，并把观察到的字节片段包装
成 `TCPFlow`/`TCPMessage` 供 addon hook、UI 和保存逻辑使用。

触发点：
- `Start`：创建 TCP flow、触发 `tcp_start` hook，并按需打开上游连接。
- `DataReceived`：记录最新 TCPMessage、触发 `tcp_message` hook，然后转发数据。
- `ConnectionClosed`：处理半关闭/全关闭，并最终触发 `tcp_end`。
- `TcpMessageInjected`：用户注入 TCP 消息时触发，转换为普通 DataReceived 流程。
"""

from dataclasses import dataclass

from mitmproxy import flow
from mitmproxy import tcp
from mitmproxy.connection import Connection
from mitmproxy.connection import ConnectionState
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy.commands import StartHook
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.events import MessageInjected
from mitmproxy.proxy.utils import expect


@dataclass
class TcpStartHook(StartHook):
    """
    A TCP connection has started.

    中文说明：对应 addon 里的 `tcp_start(flow)`，在 TCP layer 开始处理连接后触发。
    """

    flow: tcp.TCPFlow


@dataclass
class TcpMessageHook(StartHook):
    """
    A TCP connection has received a message. The most recent message
    will be flow.messages[-1]. The message is user-modifiable.

    中文说明：对应 `tcp_message(flow)`，每收到一个 TCP 字节片段时触发；addon
    可以修改 `flow.messages[-1].content` 后再由 layer 转发。
    """

    flow: tcp.TCPFlow


@dataclass
class TcpEndHook(StartHook):
    """
    A TCP connection has ended.

    中文说明：对应 `tcp_end(flow)`，客户端和服务端读方向都关闭后触发。
    """

    flow: tcp.TCPFlow


@dataclass
class TcpErrorHook(StartHook):
    """
    A TCP error has occurred.

    Every TCP flow will receive either a tcp_error or a tcp_end event, but not both.

    中文说明：对应 `tcp_error(flow)`，打开上游连接失败等错误路径会触发。
    """

    flow: tcp.TCPFlow


class TcpMessageInjected(MessageInjected[tcp.TCPMessage]):
    """
    The user has injected a custom TCP message.

    中文说明：由 `inject.tcp` 命令产生，layer 会把它当作对应方向收到的数据继续处理。
    """


class TCPLayer(layer.Layer):
    """
    Simple TCP layer that just relays messages right now.

    中文说明：这是最简单的 raw TCP 转发层，不理解应用协议，只维护 TCPFlow 并
    在两端之间搬运 bytes。
    """

    flow: tcp.TCPFlow | None

    def __init__(self, context: Context, ignore: bool = False):
        """
        初始化 TCP layer。

        `ignore=True` 表示连接被 ignore_hosts 等规则忽略，只转发数据而不创建
        flow，也不会触发 TCP flow hook。
        """
        super().__init__(context)
        if ignore:
            self.flow = None
        else:
            self.flow = tcp.TCPFlow(self.context.client, self.context.server, True)

    @expect(events.Start)
    def start(self, _) -> layer.CommandGenerator[None]:
        """
        `Start` 事件入口：触发 tcp_start，并确保上游连接已建立。
        """
        if self.flow:
            yield TcpStartHook(self.flow)

        if self.context.server.timestamp_start is None:
            err = yield commands.OpenConnection(self.context.server)
            if err:
                if self.flow:
                    self.flow.error = flow.Error(str(err))
                    yield TcpErrorHook(self.flow)
                yield commands.CloseConnection(self.context.client)
                self._handle_event = self.done
                return
        self._handle_event = self.relay_messages

    _handle_event = start

    @expect(events.DataReceived, events.ConnectionClosed, TcpMessageInjected)
    def relay_messages(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        数据转发状态：处理双向数据、连接关闭和用户注入消息。
        """
        if isinstance(event, TcpMessageInjected):
            # we just spoof that we received data here and then process that regularly.
            event = events.DataReceived(
                self.context.client
                if event.message.from_client
                else self.context.server,
                event.message.content,
            )

        assert isinstance(event, events.ConnectionEvent)

        from_client = event.connection == self.context.client
        send_to: Connection
        if from_client:
            send_to = self.context.server
        else:
            send_to = self.context.client

        if isinstance(event, events.DataReceived):
            if self.flow:
                tcp_message = tcp.TCPMessage(from_client, event.data)
                self.flow.messages.append(tcp_message)
                yield TcpMessageHook(self.flow)
                yield commands.SendData(send_to, tcp_message.content)
            else:
                yield commands.SendData(send_to, event.data)

        elif isinstance(event, events.ConnectionClosed):
            all_done = not (
                (self.context.client.state & ConnectionState.CAN_READ)
                or (self.context.server.state & ConnectionState.CAN_READ)
            )
            if all_done:
                self._handle_event = self.done
                if self.context.server.state is not ConnectionState.CLOSED:
                    yield commands.CloseConnection(self.context.server)
                if self.context.client.state is not ConnectionState.CLOSED:
                    yield commands.CloseConnection(self.context.client)
                if self.flow:
                    yield TcpEndHook(self.flow)
                    self.flow.live = False
            else:
                yield commands.CloseTcpConnection(send_to, half_close=True)
        else:
            raise AssertionError(f"Unexpected event: {event}")

    @expect(events.DataReceived, events.ConnectionClosed, TcpMessageInjected)
    def done(self, _) -> layer.CommandGenerator[None]:
        """
        终止状态：连接已结束后忽略后续 TCP 相关事件。
        """
        yield from ()
