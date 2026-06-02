import time
from logging import DEBUG

from h11._receivebuffer import ReceiveBuffer

from mitmproxy import connection
from mitmproxy import http
from mitmproxy.net.http import http1
from mitmproxy.proxy import commands
from mitmproxy.proxy import context
from mitmproxy.proxy import layer
from mitmproxy.proxy import tunnel
from mitmproxy.proxy.layers import tls
from mitmproxy.proxy.layers.http._hooks import HttpConnectUpstreamHook
from mitmproxy.utils import human


class HttpUpstreamProxy(tunnel.TunnelLayer):
    """
    通过上游 HTTP(S) 代理建立隧道。

    这一层位于 mitmproxy 想要访问的目标服务器连接（`ctx.server`）和实际
    连接到的上游代理（`tunnel_connection`）之间。如果 `send_connect`
    为真，它会先和上游代理完成 HTTP/1.1 CONNECT 握手；收到 2xx 响应后，
    后续剩余字节都被视为隧道内协议数据并转发给子层。如果 `send_connect`
    为假，则只复用 `TunnelLayer` 的基础启动逻辑，这用于 upstream 模式下
    明文 absolute-form HTTP 请求不需要 CONNECT 的场景。
    """

    buf: ReceiveBuffer
    send_connect: bool
    conn: connection.Server
    tunnel_connection: connection.Server

    def __init__(
        self, ctx: context.Context, tunnel_conn: connection.Server, send_connect: bool
    ):
        """
        初始化上游代理隧道层。

        参数：
            ctx: 原始目标服务器的连接上下文。
            tunnel_conn: 实际连接到上游代理的连接对象。
            send_connect: 在转发子层流量前是否先建立 HTTP CONNECT 隧道。
        """
        super().__init__(ctx, tunnel_connection=tunnel_conn, conn=ctx.server)
        self.buf = ReceiveBuffer()
        self.send_connect = send_connect

    @classmethod
    def make(cls, ctx: context.Context, send_connect: bool) -> tunnel.LayerStack:
        """
        构造访问已配置上游代理所需的 layer 栈。

        对 `http` 上游代理，栈中只需要当前层。对 `https` 上游代理，需要
        先压入 `ServerTLSLayer`，这样发给上游代理的 CONNECT 请求本身也会
        走 TLS。
        """
        assert ctx.server.via
        scheme, address = ctx.server.via
        assert scheme in ("http", "https")

        http_proxy = connection.Server(address=address)

        stack = tunnel.LayerStack()
        if scheme == "https":
            http_proxy.alpn_offers = tls.HTTP1_ALPNS
            http_proxy.sni = address[0]
            stack /= tls.ServerTLSLayer(ctx, http_proxy)
        stack /= cls(ctx, http_proxy, send_connect)

        return stack

    def start_handshake(self) -> layer.CommandGenerator[None]:
        """
        开始上游代理隧道握手。

        如果 `send_connect` 关闭，则没有 HTTP 代理握手要做，直接执行基础
        隧道启动逻辑即可。否则这里会为 CONNECT 请求构造一个 `HTTPFlow`，
        触发 `HttpConnectUpstreamHook`，让 addon 有机会查看或修改该请求，
        然后把它序列化为 HTTP/1.1 并发送给上游代理。
        """
        if not self.send_connect:
            return (yield from super().start_handshake())
        assert self.conn.address
        flow = http.HTTPFlow(self.context.client, self.tunnel_connection)
        authority = (
            self.conn.address[0].encode("idna") + f":{self.conn.address[1]}".encode()
        )
        headers = http.Headers()
        if self.context.options.http_connect_send_host_header:
            headers.insert(0, b"Host", authority)
        flow.request = http.Request(
            host=self.conn.address[0],
            port=self.conn.address[1],
            method=b"CONNECT",
            scheme=b"",
            authority=authority,
            path=b"",
            http_version=b"HTTP/1.1",
            headers=headers,
            content=b"",
            trailers=None,
            timestamp_start=time.time(),
            timestamp_end=time.time(),
        )
        yield HttpConnectUpstreamHook(flow)
        raw = http1.assemble_request(flow.request)
        yield commands.SendData(self.tunnel_connection, raw)

    def receive_handshake_data(
        self, data: bytes
    ) -> layer.CommandGenerator[tuple[bool, str | None]]:
        """
        处理上游代理对 CONNECT 请求的响应。

        上游代理的响应可能分片到达，所以先用 `ReceiveBuffer` 累积字节。
        当缓冲区中出现完整 HTTP 响应头后，再按 HTTP/1 解析。2xx 状态码
        表示隧道建立成功；如果响应头后已经缓冲了额外字节，这些字节属于
        隧道内协议，需要立刻交给 `receive_data()` 继续处理。非 2xx 响应
        表示隧道建立失败。
        """
        if not self.send_connect:
            return (yield from super().receive_handshake_data(data))
        self.buf += data
        response_head = self.buf.maybe_extract_lines()
        if response_head:
            try:
                response = http1.read_response_head([bytes(x) for x in response_head])
            except ValueError as e:
                proxyaddr = human.format_address(self.tunnel_connection.address)
                yield commands.Log(f"{proxyaddr}: {e}")
                return False, f"Error connecting to {proxyaddr}: {e}"
            if 200 <= response.status_code < 300:
                if self.buf:
                    yield from self.receive_data(bytes(self.buf))
                    del self.buf
                return True, None
            else:
                proxyaddr = human.format_address(self.tunnel_connection.address)
                raw_resp = b"\n".join(response_head)
                yield commands.Log(f"{proxyaddr}: {raw_resp!r}", DEBUG)
                return (
                    False,
                    f"Upstream proxy {proxyaddr} refused HTTP CONNECT request: {response.status_code} {response.reason}",
                )
        else:
            return False, None
