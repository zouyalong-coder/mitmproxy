"""
DNS 协议 layer。

本模块负责解析客户端/上游的 DNS 报文，创建 `DNSFlow`，触发 DNS hook，并在
需要时把请求转发给上游 DNS 服务器。UDP DNS 一包一个报文；TCP DNS 使用两字节
长度前缀，因此这里维护请求/响应缓冲区。

触发点：
- `Start`：进入查询状态。
- `DataReceived`：解析 DNS 报文，客户端方向触发 `dns_request`，服务端方向触发 `dns_response`。
- `ConnectionClosed`：关闭对端连接并标记所有 DNSFlow 不再 live。
"""

import struct
import time
from dataclasses import dataclass
from typing import List
from typing import Literal

from mitmproxy import dns
from mitmproxy import flow as mflow
from mitmproxy.net.dns import response_codes
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.utils import expect

_LENGTH_LABEL = struct.Struct("!H")


@dataclass
class DnsRequestHook(commands.StartHook):
    """
    A DNS query has been received.

    中文说明：对应 addon 里的 `dns_request(flow)`，客户端 DNS 查询解析完成后触发。
    """

    flow: dns.DNSFlow


@dataclass
class DnsResponseHook(commands.StartHook):
    """
    A DNS response has been received or set.

    中文说明：对应 `dns_response(flow)`，上游响应到达或 addon 直接设置 response 后触发。
    """

    flow: dns.DNSFlow


@dataclass
class DnsErrorHook(commands.StartHook):
    """
    A DNS error has occurred.

    中文说明：对应 `dns_error(flow)`，解析、连接或处理失败时触发。
    """

    flow: dns.DNSFlow


def pack_message(
    message: dns.DNSMessage, transport_protocol: Literal["tcp", "udp"]
) -> bytes:
    """
    将 DNSMessage 打包为对应传输协议的 wire bytes。

    TCP DNS 需要在报文前加 2 字节长度字段；UDP DNS 直接发送报文本体。
    """
    packed = message.packed
    if transport_protocol == "tcp":
        return struct.pack("!H", len(packed)) + packed
    else:
        return packed


class DNSLayer(layer.Layer):
    """
    Layer that handles resolving DNS queries.

    中文说明：管理多个 DNSFlow，以 DNS message id 关联请求和响应，并把 hook
    设置的响应或错误转换为返回给客户端的 DNS 报文。
    """

    flows: dict[int, dns.DNSFlow]
    req_buf: bytearray
    resp_buf: bytearray

    def __init__(self, context: Context):
        """
        初始化 DNS layer 的 flow 映射和 TCP 缓冲区。
        """
        super().__init__(context)
        self.flows = {}
        self.req_buf = bytearray()
        self.resp_buf = bytearray()

    def handle_request(
        self, flow: dns.DNSFlow, msg: dns.DNSMessage
    ) -> layer.CommandGenerator[None]:
        """
        处理客户端 DNS 请求：触发 hook、短路响应或转发上游。
        """
        flow.request = msg  # if already set, continue and query upstream again
        yield DnsRequestHook(flow)
        if flow.response:
            yield from self.handle_response(flow, flow.response)
        elif flow.error:
            yield from self.handle_error(flow, flow.error.msg)
        elif not self.context.server.address:
            yield from self.handle_error(
                flow, "No hook has set a response and there is no upstream server."
            )
        else:
            if not self.context.server.connected:
                err = yield commands.OpenConnection(self.context.server)
                if err:
                    yield from self.handle_error(flow, str(err))
                    # cannot recover from this
                    return
            packed = pack_message(flow.request, flow.server_conn.transport_protocol)
            yield commands.SendData(self.context.server, packed)

    def handle_response(
        self, flow: dns.DNSFlow, msg: dns.DNSMessage
    ) -> layer.CommandGenerator[None]:
        """
        处理 DNS 响应：触发 hook，并把最终响应发回客户端。
        """
        flow.response = msg
        yield DnsResponseHook(flow)
        if flow.response:
            packed = pack_message(flow.response, flow.client_conn.transport_protocol)
            yield commands.SendData(self.context.client, packed)

    def handle_error(self, flow: dns.DNSFlow, err: str) -> layer.CommandGenerator[None]:
        """
        处理 DNS 错误：触发 dns_error，并向客户端返回 SERVFAIL。
        """
        flow.error = mflow.Error(err)
        yield DnsErrorHook(flow)
        servfail = flow.request.fail(response_codes.SERVFAIL)
        yield commands.SendData(
            self.context.client,
            pack_message(servfail, flow.client_conn.transport_protocol),
        )

    def unpack_message(self, data: bytes, from_client: bool) -> List[dns.DNSMessage]:
        """
        从原始传输数据中解析出一个或多个 DNSMessage。

        UDP 直接解析单个 datagram；TCP 会把数据追加到方向对应的缓冲区，并按
        两字节长度前缀尽可能拆出完整报文。
        """
        msgs: List[dns.DNSMessage] = []

        buf = self.req_buf if from_client else self.resp_buf

        if self.context.client.transport_protocol == "udp":
            msgs.append(dns.DNSMessage.unpack(data, timestamp=time.time()))
        elif self.context.client.transport_protocol == "tcp":
            buf.extend(data)
            size = len(buf)
            offset = 0

            while True:
                if size - offset < _LENGTH_LABEL.size:
                    break
                (expected_size,) = _LENGTH_LABEL.unpack_from(buf, offset)
                offset += _LENGTH_LABEL.size
                if expected_size == 0:
                    raise struct.error("Message length field cannot be zero")

                if size - offset < expected_size:
                    offset -= _LENGTH_LABEL.size
                    break

                data = bytes(buf[offset : expected_size + offset])
                offset += expected_size
                msgs.append(dns.DNSMessage.unpack(data, timestamp=time.time()))

            del buf[:offset]
        return msgs

    @expect(events.Start)
    def state_start(self, _) -> layer.CommandGenerator[None]:
        """
        `Start` 事件入口：切换到 DNS 查询处理状态。
        """
        self._handle_event = self.state_query
        yield from ()

    @expect(events.DataReceived, events.ConnectionClosed)
    def state_query(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        DNS 查询状态：处理双向数据和连接关闭。
        """
        assert isinstance(event, events.ConnectionEvent)
        from_client = event.connection is self.context.client

        if isinstance(event, events.DataReceived):
            msgs: List[dns.DNSMessage] = []
            try:
                msgs = self.unpack_message(event.data, from_client)
            except struct.error as e:
                yield commands.Log(f"{event.connection} sent an invalid message: {e}")
                yield commands.CloseConnection(event.connection)
                self._handle_event = self.state_done
            else:
                for msg in msgs:
                    try:
                        flow = self.flows[msg.id]
                    except KeyError:
                        flow = dns.DNSFlow(
                            self.context.client, self.context.server, live=True
                        )
                        self.flows[msg.id] = flow
                    if from_client:
                        yield from self.handle_request(flow, msg)
                    else:
                        yield from self.handle_response(flow, msg)

        elif isinstance(event, events.ConnectionClosed):
            other_conn = self.context.server if from_client else self.context.client
            if other_conn.connected:
                yield commands.CloseConnection(other_conn)
            self._handle_event = self.state_done
            for flow in self.flows.values():
                flow.live = False

        else:
            raise AssertionError(f"Unexpected event: {event}")

    @expect(events.DataReceived, events.ConnectionClosed)
    def state_done(self, _) -> layer.CommandGenerator[None]:
        """
        终止状态：DNS layer 结束后忽略后续事件。
        """
        yield from ()

    _handle_event = state_start
