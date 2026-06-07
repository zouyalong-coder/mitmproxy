"""
UDP 原始转发 layer。

本模块负责转发 UDP 数据报，并把每个数据报记录为 `UDPFlow.messages` 中的
`UDPMessage`。与 TCP 不同，UDP 的 message 边界就是真实 datagram 边界。

触发点：
- `Start`：创建 UDP flow、触发 `udp_start` hook，并按需打开上游连接。
- `DataReceived`：记录数据报、触发 `udp_message` hook，然后转发数据。
- `ConnectionClosed`：关闭对端并触发 `udp_end`。
- `UdpMessageInjected`：用户注入 UDP 数据报时触发，转换为普通 DataReceived 流程。
"""

from dataclasses import dataclass

from mitmproxy import flow
from mitmproxy import udp
from mitmproxy.connection import Connection
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy.commands import StartHook
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.events import MessageInjected
from mitmproxy.proxy.utils import expect


@dataclass
class UdpStartHook(StartHook):
    """
    A UDP connection has started.

    中文说明：对应 addon 里的 `udp_start(flow)`，UDP flow 创建后触发。
    """

    flow: udp.UDPFlow


@dataclass
class UdpMessageHook(StartHook):
    """
    A UDP connection has received a message. The most recent message
    will be flow.messages[-1]. The message is user-modifiable.

    中文说明：对应 `udp_message(flow)`，每个 UDP 数据报到达时触发。
    """

    flow: udp.UDPFlow


@dataclass
class UdpEndHook(StartHook):
    """
    A UDP connection has ended.

    中文说明：对应 `udp_end(flow)`，UDP flow 关闭时触发。
    """

    flow: udp.UDPFlow


@dataclass
class UdpErrorHook(StartHook):
    """
    A UDP error has occurred.

    Every UDP flow will receive either a udp_error or a udp_end event, but not both.

    中文说明：对应 `udp_error(flow)`，例如打开上游连接失败时触发。
    """

    flow: udp.UDPFlow


class UdpMessageInjected(MessageInjected[udp.UDPMessage]):
    """
    The user has injected a custom UDP message.

    中文说明：由 `inject.udp` 命令产生，layer 会把它当作指定方向收到的数据报处理。
    """


class UDPLayer(layer.Layer):
    """
    Simple UDP layer that just relays messages right now.

    中文说明：不解析上层协议，只在两端之间转发 UDP datagram，并按需触发 flow hook。
    """

    flow: udp.UDPFlow | None

    def __init__(self, context: Context, ignore: bool = False):
        """
        初始化 UDP layer。

        `ignore=True` 时只转发，不创建 UDPFlow，也不触发 UDP flow hook。
        """
        super().__init__(context)
        if ignore:
            self.flow = None
        else:
            self.flow = udp.UDPFlow(self.context.client, self.context.server, True)

    @expect(events.Start)
    def start(self, _) -> layer.CommandGenerator[None]:
        """
        `Start` 事件入口：触发 udp_start，并确保上游 UDP 连接对象已打开。
        """
        if self.flow:
            yield UdpStartHook(self.flow)

        if self.context.server.timestamp_start is None:
            err = yield commands.OpenConnection(self.context.server)
            if err:
                if self.flow:
                    self.flow.error = flow.Error(str(err))
                    yield UdpErrorHook(self.flow)
                yield commands.CloseConnection(self.context.client)
                self._handle_event = self.done
                return
        self._handle_event = self.relay_messages

    _handle_event = start

    @expect(events.DataReceived, events.ConnectionClosed, UdpMessageInjected)
    def relay_messages(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        数据转发状态：处理 UDP 数据报、关闭事件和用户注入消息。
        """
        if isinstance(event, UdpMessageInjected):
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
                udp_message = udp.UDPMessage(from_client, event.data)
                self.flow.messages.append(udp_message)
                yield UdpMessageHook(self.flow)
                yield commands.SendData(send_to, udp_message.content)
            else:
                yield commands.SendData(send_to, event.data)

        elif isinstance(event, events.ConnectionClosed):
            self._handle_event = self.done
            yield commands.CloseConnection(send_to)
            if self.flow:
                yield UdpEndHook(self.flow)
                self.flow.live = False
        else:
            raise AssertionError(f"Unexpected event: {event}")

    @expect(events.DataReceived, events.ConnectionClosed, UdpMessageInjected)
    def done(self, _) -> layer.CommandGenerator[None]:
        """
        终止状态：UDP flow 结束后忽略后续事件。
        """
        yield from ()
