"""
HTTP 协议 layer 主状态机。

本模块把 HTTP/1、HTTP/2、HTTP/3 连接解析器产生的 `HttpEvent` 统一汇入
`HttpStream`，创建/更新 `HTTPFlow`，触发 request/response/connect/error hook，
并通过 `HttpLayer` 管理多路复用 stream、连接复用和上游连接获取。

触发点：
- 底层解析器通过 `ReceiveHttp` 送入 Request/Response 事件。
- `HttpStream` 在合适时机触发 `requestheaders/request/responseheaders/response/error`。
- CONNECT 请求会触发 `http_connect/http_connected/http_connect_error`。
- `HttpLayer` 处理 `GetHttpConnection`、`SendHttp`、`DropStream` 等内部命令。
"""

import collections
import enum
import time
from dataclasses import dataclass
from functools import cached_property
from logging import DEBUG
from logging import WARNING

import wsproto.handshake

from ...context import Context
from ...mode_specs import ReverseMode
from ...mode_specs import UpstreamMode
from ..quic import QuicStreamEvent
from ._base import HttpCommand
from ._base import HttpConnection
from ._base import ReceiveHttp
from ._base import StreamId
from ._events import ErrorCode
from ._events import HttpEvent
from ._events import RequestData
from ._events import RequestEndOfMessage
from ._events import RequestHeaders
from ._events import RequestProtocolError
from ._events import RequestTrailers
from ._events import ResponseData
from ._events import ResponseEndOfMessage
from ._events import ResponseHeaders
from ._events import ResponseProtocolError
from ._events import ResponseTrailers
from ._hooks import HttpConnectedHook
from ._hooks import HttpConnectErrorHook
from ._hooks import HttpConnectHook
from ._hooks import HttpErrorHook
from ._hooks import HttpRequestHeadersHook
from ._hooks import HttpRequestHook
from ._hooks import HttpResponseHeadersHook
from ._hooks import HttpResponseHook
from ._http1 import Http1Client
from ._http1 import Http1Connection
from ._http1 import Http1Server
from ._http2 import Http2Client
from ._http2 import Http2Server
from ._http3 import Http3Client
from ._http3 import Http3Server
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.connection import Connection
from mitmproxy.connection import Server
from mitmproxy.connection import TransportProtocol
from mitmproxy.net import server_spec
from mitmproxy.net.http import url
from mitmproxy.net.http.http1 import expected_http_body_size
from mitmproxy.net.http.validate import validate_headers
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy import tunnel
from mitmproxy.proxy.layers import quic
from mitmproxy.proxy.layers import tcp
from mitmproxy.proxy.layers import tls
from mitmproxy.proxy.layers import websocket
from mitmproxy.proxy.layers.http import _upstream_proxy
from mitmproxy.proxy.utils import expect
from mitmproxy.proxy.utils import ReceiveBuffer
from mitmproxy.utils import human
from mitmproxy.websocket import WebSocketData


class HTTPMode(enum.Enum):
    """
    HTTP layer 的运行模式。

    regular 表示显式代理，transparent 表示目标已知模式，upstream 表示请求需要
    发往上游 HTTP 代理。
    """

    regular = 1
    transparent = 2
    upstream = 3


def validate_request(
    mode: HTTPMode, request: http.Request, validate_inbound_headers: bool
) -> str | None:
    """
    校验客户端请求是否适合当前 HTTP 模式。

    返回字符串表示错误原因，返回 None 表示请求有效。
    """
    if request.scheme not in ("http", "https", ""):
        return f"Invalid request scheme: {request.scheme}"
    if mode is HTTPMode.transparent and request.method == "CONNECT":
        return (
            f"mitmproxy received an HTTP CONNECT request even though it is not running in regular/upstream mode. "
            f"This usually indicates a misconfiguration, please see the mitmproxy mode documentation for details."
        )
    if validate_inbound_headers:
        try:
            validate_headers(request)
        except ValueError as e:
            return (
                f"Received {e} from client, refusing to prevent request smuggling attacks. "
                "Disable the validate_inbound_headers option to skip this security check."
            )
    return None


def is_h3_alpn(alpn: bytes | None) -> bool:
    """
    判断 ALPN 是否表示 HTTP/3 或其草案版本。
    """
    return alpn == b"h3" or (alpn is not None and alpn.startswith(b"h3-"))


@dataclass
class GetHttpConnection(HttpCommand):
    """
    Open an HTTP Connection. This may not actually open a connection, but return an existing HTTP connection instead.

    中文说明：HttpStream 用它向 HttpLayer 申请一个可用上游 HTTP 连接；HttpLayer
    可以复用已有连接，也可以打开新连接。
    """

    blocking = True
    address: tuple[str, int]
    tls: bool
    via: server_spec.ServerSpec | None
    transport_protocol: TransportProtocol = "tcp"

    def __hash__(self):
        return id(self)

    def connection_spec_matches(self, connection: Connection) -> bool:
        """
        判断已有连接是否满足本次请求的目标地址、TLS、上游代理和传输协议要求。
        """
        return (
            isinstance(connection, Server)
            and self.address == connection.address
            and self.tls == connection.tls
            and self.via == connection.via
            and self.transport_protocol == connection.transport_protocol
        )


@dataclass
class GetHttpConnectionCompleted(events.CommandCompleted):
    """
    GetHttpConnection 的完成事件，返回连接对象或错误信息。
    """

    command: GetHttpConnection
    reply: tuple[None, str] | tuple[Connection, None]
    """connection object, error message"""


@dataclass
class RegisterHttpConnection(HttpCommand):
    """
    Register that a HTTP connection attempt has been completed.

    中文说明：HttpLayer 用它记录连接建立结果，方便后续复用或错误处理。
    """

    connection: Connection
    err: str | None


@dataclass
class SendHttp(HttpCommand):
    """
    将一个 HttpEvent 发送到指定 HTTP 连接解析器。
    """

    event: HttpEvent
    connection: Connection

    def __repr__(self) -> str:
        return f"Send({self.event})"


@dataclass
class DropStream(HttpCommand):
    """
    Signal to the HTTP layer that this stream is done processing and can be dropped from memory.

    中文说明：HttpStream 完成后通知 HttpLayer 可以释放对应 stream_id 的状态。
    """

    stream_id: StreamId


class HttpStream(layer.Layer):
    """
    单个 HTTP 请求/响应 stream 的状态机。

    HTTP/1 一个连接通常只有一个活跃 stream，HTTP/2/3 可以有多个。该类负责把
    头、数据、trailers、end-of-message 组装成 HTTPFlow，并在正确时机触发 hook。
    """

    request_body_buf: ReceiveBuffer
    response_body_buf: ReceiveBuffer
    flow: http.HTTPFlow
    stream_id: StreamId
    child_layer: layer.Layer | None = None

    @cached_property
    def mode(self) -> HTTPMode:
        i = self.context.layers.index(self)
        parent = self.context.layers[i - 1]
        assert isinstance(parent, HttpLayer)
        return parent.mode

    def __init__(self, context: Context, stream_id: int) -> None:
        """
        初始化请求/响应 body 缓冲区和双向状态机。
        """
        super().__init__(context)
        self.request_body_buf = ReceiveBuffer()
        self.response_body_buf = ReceiveBuffer()
        self.client_state = self.state_uninitialized
        self.server_state = self.state_uninitialized
        self.stream_id = stream_id

    def __repr__(self):
        if self._handle_event == self.passthrough:
            return f"HttpStream(id={self.stream_id}, passthrough)"
        else:
            return (
                f"HttpStream("
                f"id={self.stream_id}, "
                f"client_state={self.client_state.__name__}, "
                f"server_state={self.server_state.__name__}"
                f")"
            )

    @expect(events.Start, HttpEvent)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        HttpStream 总入口：按事件方向分发到客户端侧或服务端侧状态函数。
        """
        if isinstance(event, events.Start):
            self.client_state = self.state_wait_for_request_headers
        elif isinstance(event, (RequestProtocolError, ResponseProtocolError)):
            yield from self.handle_protocol_error(event)
        elif isinstance(
            event, (RequestHeaders, RequestData, RequestTrailers, RequestEndOfMessage)
        ):
            yield from self.client_state(event)
        else:
            yield from self.server_state(event)

    @expect(RequestHeaders)
    def state_wait_for_request_headers(
        self, event: RequestHeaders
    ) -> layer.CommandGenerator[None]:
        """
        等待请求头状态：创建 HTTPFlow、补全目标信息并处理 CONNECT/普通请求。
        """
        if not event.replay_flow:
            self.flow = http.HTTPFlow(self.context.client, self.context.server)

        else:
            self.flow = event.replay_flow
        self.flow.request = event.request
        self.flow.live = True

        if (yield from self.check_invalid(True)):
            return

        if self.flow.request.method == "CONNECT":
            return (yield from self.handle_connect())

        if self.mode is HTTPMode.transparent:
            # Determine .scheme, .host and .port attributes for transparent requests
            assert self.context.server.address
            self.flow.request.data.host = self.context.server.address[0]
            self.flow.request.data.port = self.context.server.address[1]
            self.flow.request.scheme = "https" if self.context.server.tls else "http"
        elif not self.flow.request.host:
            # We need to extract destination information from the host header.
            try:
                host, port = url.parse_authority(
                    self.flow.request.host_header or "", check=True
                )
            except ValueError:
                yield SendHttp(
                    ResponseProtocolError(
                        self.stream_id,
                        "HTTP request has no host header, destination unknown.",
                        ErrorCode.DESTINATION_UNKNOWN,
                    ),
                    self.context.client,
                )
                self.client_state = self.state_errored
                return
            else:
                if port is None:
                    port = 443 if self.context.client.tls else 80
                self.flow.request.data.host = host
                self.flow.request.data.port = port
                self.flow.request.scheme = (
                    "https" if self.context.client.tls else "http"
                )

        if self.mode is HTTPMode.regular and not (
            self.flow.request.is_http2 or self.flow.request.is_http3
        ):
            # Set the request target to origin-form for HTTP/1, some servers don't support absolute-form requests.
            # see https://github.com/mitmproxy/mitmproxy/issues/1759
            self.flow.request.authority = ""

        # update host header in reverse proxy mode
        if (
            isinstance(self.context.client.proxy_mode, ReverseMode)
            and not self.context.options.keep_host_header
        ):
            assert self.context.server.address
            self.flow.request.host_header = url.hostport(
                "https" if self.context.server.tls else "http",
                self.context.server.address[0],
                self.context.server.address[1],
            )

        if not event.end_stream and (yield from self.check_body_size(True)):
            return

        yield HttpRequestHeadersHook(self.flow)
        if (yield from self.check_killed(True)):
            return

        if self.flow.request.headers.get("expect", "").lower() == "100-continue":
            continue_response = http.Response.make(100)
            continue_response.headers.clear()
            yield SendHttp(
                ResponseHeaders(self.stream_id, continue_response), self.context.client
            )
            self.flow.request.headers.pop("expect")

        if self.flow.request.stream and not event.end_stream:
            yield from self.start_request_stream()
        else:
            self.client_state = self.state_consume_request_body
        self.server_state = self.state_wait_for_response_headers

    def start_request_stream(self) -> layer.CommandGenerator[None]:
        """
        开启请求体流式转发。

        触发点：requestheaders hook 后，如果 addon 或配置要求流式处理请求体，
        后续 `RequestData` 会边到达边发送到服务器。
        """
        if self.flow.response:
            raise NotImplementedError(
                "Can't set a response and enable streaming at the same time."
            )
        ok = yield from self.make_server_connection()
        if not ok:
            self.client_state = self.state_errored
            return
        yield SendHttp(
            RequestHeaders(self.stream_id, self.flow.request, end_stream=False),
            self.context.server,
        )
        yield commands.Log(f"Streaming request to {self.flow.request.host}.")
        self.client_state = self.state_stream_request_body

    @expect(RequestData, RequestTrailers, RequestEndOfMessage)
    def state_stream_request_body(
        self, event: RequestData | RequestEndOfMessage
    ) -> layer.CommandGenerator[None]:
        """
        流式请求体状态：逐块处理客户端 body，并在结束时触发 request hook。
        """
        if isinstance(event, RequestData):
            if callable(self.flow.request.stream):
                chunks = self.flow.request.stream(event.data)
                if isinstance(chunks, bytes):
                    chunks = [chunks]
            else:
                chunks = [event.data]
            for chunk in chunks:
                if self.context.options.store_streamed_bodies:
                    self.request_body_buf += chunk
                yield SendHttp(RequestData(self.stream_id, chunk), self.context.server)
        elif isinstance(event, RequestTrailers):
            # we don't do anything further here, we wait for RequestEndOfMessage first to trigger the request hook.
            self.flow.request.trailers = event.trailers
        elif isinstance(event, RequestEndOfMessage):
            if callable(self.flow.request.stream):
                chunks = self.flow.request.stream(b"")
                if chunks == b"":
                    chunks = []
                elif isinstance(chunks, bytes):
                    chunks = [chunks]
                for chunk in chunks:
                    if self.context.options.store_streamed_bodies:
                        self.request_body_buf += chunk
                    yield SendHttp(
                        RequestData(self.stream_id, chunk), self.context.server
                    )

            if self.context.options.store_streamed_bodies:
                self.flow.request.data.content = bytes(self.request_body_buf)
                self.request_body_buf.clear()
            self.flow.request.timestamp_end = time.time()
            yield HttpRequestHook(self.flow)
            self.client_state = self.state_done

            if self.flow.request.trailers:
                # we've delayed sending trailers until after `request` has been triggered.
                yield SendHttp(
                    RequestTrailers(self.stream_id, self.flow.request.trailers),
                    self.context.server,
                )
            yield SendHttp(event, self.context.server)

            if self.server_state == self.state_done:
                yield from self.flow_done()

    @expect(RequestData, RequestTrailers, RequestEndOfMessage)
    def state_consume_request_body(
        self, event: events.Event
    ) -> layer.CommandGenerator[None]:
        """
        缓冲请求体状态：收完整个请求 body 后再触发 request hook。

        addon 可以在 request hook 中直接设置 `flow.response`，此时请求不会继续
        发往服务器，而是进入本地响应发送流程。
        """
        if isinstance(event, RequestData):
            self.request_body_buf += event.data
            yield from self.check_body_size(True)
        elif isinstance(event, RequestTrailers):
            assert self.flow.request
            self.flow.request.trailers = event.trailers
        elif isinstance(event, RequestEndOfMessage):
            self.flow.request.timestamp_end = time.time()
            self.flow.request.data.content = bytes(self.request_body_buf)
            self.request_body_buf.clear()
            self.client_state = self.state_done
            yield HttpRequestHook(self.flow)
            if (yield from self.check_killed(True)):
                return
            elif self.flow.response:
                # response was set by an inline script.
                # we now need to emulate the responseheaders hook.
                self.flow.response.timestamp_start = time.time()
                yield HttpResponseHeadersHook(self.flow)
                if (yield from self.check_killed(True)):
                    return
                yield from self.send_response()
            else:
                ok = yield from self.make_server_connection()
                if not ok:
                    return

                content = self.flow.request.raw_content
                done_after_headers = not (content or self.flow.request.trailers)
                yield SendHttp(
                    RequestHeaders(
                        self.stream_id, self.flow.request, done_after_headers
                    ),
                    self.context.server,
                )
                if content:
                    yield SendHttp(
                        RequestData(self.stream_id, content), self.context.server
                    )
                if self.flow.request.trailers:
                    yield SendHttp(
                        RequestTrailers(self.stream_id, self.flow.request.trailers),
                        self.context.server,
                    )
                yield SendHttp(RequestEndOfMessage(self.stream_id), self.context.server)

    @expect(ResponseHeaders)
    def state_wait_for_response_headers(
        self, event: ResponseHeaders
    ) -> layer.CommandGenerator[None]:
        """
        等待响应头状态：收到服务器响应头后触发 responseheaders hook。
        """
        self.flow.response = event.response

        if not event.end_stream and (yield from self.check_body_size(False)):
            return
        if (yield from self.check_invalid(False)):
            return

        yield HttpResponseHeadersHook(self.flow)
        if (yield from self.check_killed(True)):
            return

        elif self.flow.response.stream and not event.end_stream:
            yield from self.start_response_stream()
        else:
            self.server_state = self.state_consume_response_body

    def start_response_stream(self) -> layer.CommandGenerator[None]:
        """
        开启响应体流式转发。

        触发点：responseheaders hook 后，如果响应被标记为 stream，后续
        `ResponseData` 会边到达边转给客户端。
        """
        assert self.flow.response
        yield SendHttp(
            ResponseHeaders(self.stream_id, self.flow.response, end_stream=False),
            self.context.client,
        )
        yield commands.Log(f"Streaming response from {self.flow.request.host}.")
        self.server_state = self.state_stream_response_body

    @expect(ResponseData, ResponseTrailers, ResponseEndOfMessage)
    def state_stream_response_body(
        self, event: events.Event
    ) -> layer.CommandGenerator[None]:
        """
        流式响应体状态：逐块处理服务器 body，并在结束时触发 response hook。
        """
        assert self.flow.response
        if isinstance(event, ResponseData):
            if callable(self.flow.response.stream):
                chunks = self.flow.response.stream(event.data)
                if isinstance(chunks, bytes):
                    chunks = [chunks]
            else:
                chunks = [event.data]
            for chunk in chunks:
                if self.context.options.store_streamed_bodies:
                    self.response_body_buf += chunk
                yield SendHttp(ResponseData(self.stream_id, chunk), self.context.client)
        elif isinstance(event, ResponseTrailers):
            self.flow.response.trailers = event.trailers
            # will be sent in send_response() after the response hook.
        elif isinstance(event, ResponseEndOfMessage):
            if callable(self.flow.response.stream):
                chunks = self.flow.response.stream(b"")
                if chunks == b"":
                    chunks = []
                elif isinstance(chunks, bytes):
                    chunks = [chunks]
                for chunk in chunks:
                    if self.context.options.store_streamed_bodies:
                        self.response_body_buf += chunk
                    yield SendHttp(
                        ResponseData(self.stream_id, chunk), self.context.client
                    )
            if self.context.options.store_streamed_bodies:
                self.flow.response.data.content = bytes(self.response_body_buf)
                self.response_body_buf.clear()
            yield from self.send_response(already_streamed=True)

    @expect(ResponseData, ResponseTrailers, ResponseEndOfMessage)
    def state_consume_response_body(
        self, event: events.Event
    ) -> layer.CommandGenerator[None]:
        """
        缓冲响应体状态：收完整个响应 body 后再统一发送给客户端。
        """
        if isinstance(event, ResponseData):
            self.response_body_buf += event.data
            yield from self.check_body_size(False)
        elif isinstance(event, ResponseTrailers):
            assert self.flow.response
            self.flow.response.trailers = event.trailers
        elif isinstance(event, ResponseEndOfMessage):
            assert self.flow.response
            self.flow.response.data.content = bytes(self.response_body_buf)
            self.response_body_buf.clear()
            yield from self.send_response()

    def send_response(self, already_streamed: bool = False):
        """
        We have either consumed the entire response from the server or the response was set by an addon.

        中文说明：触发 response hook，识别 WebSocket 升级，并把响应头、body、
        trailers 和 EOM 写回客户端。
        """
        assert self.flow.response
        self.flow.response.timestamp_end = time.time()

        is_websocket = (
            self.flow.response.status_code == 101
            and self.flow.response.headers.get("upgrade", "").lower() == "websocket"
            and self.flow.request.headers.get("Sec-WebSocket-Version", "").encode()
            == wsproto.handshake.WEBSOCKET_VERSION
            and self.context.options.websocket
        )
        if is_websocket:
            # We need to set this before calling the response hook
            # so that addons can determine if a WebSocket connection is following up.
            self.flow.websocket = WebSocketData()

        yield HttpResponseHook(self.flow)
        self.server_state = self.state_done
        if (yield from self.check_killed(False)):
            return

        if not already_streamed:
            content = self.flow.response.raw_content
            done_after_headers = not (content or self.flow.response.trailers)
            yield SendHttp(
                ResponseHeaders(self.stream_id, self.flow.response, done_after_headers),
                self.context.client,
            )
            if content:
                yield SendHttp(
                    ResponseData(self.stream_id, content), self.context.client
                )

        if self.flow.response.trailers:
            yield SendHttp(
                ResponseTrailers(self.stream_id, self.flow.response.trailers),
                self.context.client,
            )

        if self.client_state == self.state_done:
            yield from self.flow_done()

    def flow_done(self) -> layer.CommandGenerator[None]:
        """
        完成一个 HTTP flow，并在协议升级时切换到子 layer。

        触发点：请求侧和响应侧都结束后调用。101 响应会把后续字节交给
        WebSocket 或 TCP layer；普通 HTTP flow 则发送 `DropStream` 释放状态。
        """
        if not self.flow.websocket:
            self.flow.live = False

        assert self.flow.response
        if self.flow.response.status_code == 101:
            if self.flow.websocket:
                self.child_layer = websocket.WebsocketLayer(self.context, self.flow)
            elif self.context.options.rawtcp:
                self.child_layer = tcp.TCPLayer(self.context)
            else:
                yield commands.Log(
                    f"Sent HTTP 101 response, but no protocol is enabled to upgrade to.",
                    WARNING,
                )
                yield commands.CloseConnection(self.context.client)
                self.client_state = self.server_state = self.state_errored
                return
            if self.debug:
                yield commands.Log(
                    f"{self.debug}[http] upgrading to {self.child_layer}", DEBUG
                )
            self._handle_event = self.passthrough
            yield from self.child_layer.handle_event(events.Start())
        else:
            yield DropStream(self.stream_id)

        # delay sending EOM until the child layer is set up,
        # we may get data immediately and need to be prepared to handle it.
        yield SendHttp(ResponseEndOfMessage(self.stream_id), self.context.client)

    def check_body_size(self, request: bool) -> layer.CommandGenerator[bool]:
        """
        Check if the body size exceeds limits imposed by stream_large_bodies or body_size_limit.

        Returns `True` if the body size exceeds body_size_limit and further processing should be stopped.
        """
        if not (
            self.context.options.stream_large_bodies
            or self.context.options.body_size_limit
        ):
            return False

        # Step 1: Determine the expected body size. This can either come from a known content-length header,
        # or from the amount of currently buffered bytes (e.g. for chunked encoding).
        response = not request
        expected_size: int | None
        # the 'late' case: we already started consuming the body
        if request and self.request_body_buf:
            expected_size = len(self.request_body_buf)
        elif response and self.response_body_buf:
            expected_size = len(self.response_body_buf)
        else:
            # the 'early' case: we have not started consuming the body
            try:
                expected_size = expected_http_body_size(
                    self.flow.request, self.flow.response if response else None
                )
            except ValueError:  # pragma: no cover
                # we just don't stream/kill malformed content-length headers.
                expected_size = None

        if expected_size is None or expected_size <= 0:
            return False

        # Step 2: Do we need to abort this?
        max_total_size = human.parse_size(self.context.options.body_size_limit)
        if max_total_size is not None and expected_size > max_total_size:
            if request and not self.request_body_buf:
                yield HttpRequestHeadersHook(self.flow)
            if response and not self.response_body_buf:
                yield HttpResponseHeadersHook(self.flow)

            err_msg = f"{'Request' if request else 'Response'} body exceeds mitmproxy's body_size_limit."
            err_code = (
                ErrorCode.REQUEST_TOO_LARGE if request else ErrorCode.RESPONSE_TOO_LARGE
            )

            self.flow.error = flow.Error(err_msg)
            yield HttpErrorHook(self.flow)
            yield SendHttp(
                ResponseProtocolError(self.stream_id, err_msg, err_code),
                self.context.client,
            )
            self.client_state = self.state_errored
            if response:
                yield SendHttp(
                    RequestProtocolError(self.stream_id, err_msg, err_code),
                    self.context.server,
                )
                self.server_state = self.state_errored
            self.flow.live = False
            return True

        # Step 3: Do we need to stream this?
        max_stream_size = human.parse_size(self.context.options.stream_large_bodies)
        if max_stream_size is not None and expected_size > max_stream_size:
            if request:
                self.flow.request.stream = True
                if self.request_body_buf:
                    # clear buffer and then fake a DataReceived event with everything we had in the buffer so far.
                    body_buf = bytes(self.request_body_buf)
                    self.request_body_buf.clear()
                    yield from self.start_request_stream()
                    yield from self.handle_event(RequestData(self.stream_id, body_buf))
            if response:
                assert self.flow.response
                self.flow.response.stream = True
                if self.response_body_buf:
                    body_buf = bytes(self.response_body_buf)
                    self.response_body_buf.clear()
                    yield from self.start_response_stream()
                    yield from self.handle_event(ResponseData(self.stream_id, body_buf))
        return False

    def check_invalid(self, request: bool) -> layer.CommandGenerator[bool]:
        """
        校验请求/响应头是否合法，发现请求走私风险时终止 flow。
        """
        err: str | None = None
        if request:
            err = validate_request(
                self.mode,
                self.flow.request,
                self.context.options.validate_inbound_headers,
            )
        elif self.context.options.validate_inbound_headers:
            assert self.flow.response is not None
            try:
                validate_headers(self.flow.response)
            except ValueError as e:
                err = (
                    f"Received {e} from server, refusing to prevent request smuggling attacks. "
                    "Disable the validate_inbound_headers option to skip this security check."
                )

        if err:
            self.flow.error = flow.Error(err)

            if request:
                # flow has not been seen yet, register it.
                yield HttpRequestHeadersHook(self.flow)
            else:
                # immediately kill server connection
                yield commands.CloseConnection(self.flow.server_conn)
            yield HttpErrorHook(self.flow)
            yield SendHttp(
                ResponseProtocolError(
                    self.stream_id,
                    err,
                    ErrorCode.REQUEST_VALIDATION_FAILED
                    if request
                    else ErrorCode.RESPONSE_VALIDATION_FAILED,
                ),
                self.context.client,
            )
            self.flow.live = False
            self.client_state = self.server_state = self.state_errored
            return True
        else:
            return False

    def check_killed(self, emit_error_hook: bool) -> layer.CommandGenerator[bool]:
        """
        检查 flow 是否被 addon 或远端关闭终止。

        hook 等待期间事件会进入 `_paused_event_queue`，这里会窥探队列判断
        客户端是否已经断开，以免继续处理已经死亡的 flow。
        """
        killed_by_us = (
            self.flow.error and self.flow.error.msg == flow.Error.KILLED_MESSAGE
        )
        # The client may have closed the connection while we were waiting for the hook to complete.
        # We peek into the event queue to see if that is the case.
        killed_by_remote = None
        for evt in self._paused_event_queue:
            if isinstance(evt, RequestProtocolError):
                killed_by_remote = evt.message
                break

        if killed_by_remote:
            if not self.flow.error:
                self.flow.error = flow.Error(killed_by_remote)
        if killed_by_us or killed_by_remote:
            if emit_error_hook:
                yield HttpErrorHook(self.flow)
            yield SendHttp(
                ResponseProtocolError(self.stream_id, "killed", ErrorCode.KILL),
                self.context.client,
            )
            self.flow.live = False
            self.client_state = self.server_state = self.state_errored
            return True
        return False

    def handle_protocol_error(
        self, event: RequestProtocolError | ResponseProtocolError
    ) -> layer.CommandGenerator[None]:
        """
        统一处理客户端侧或服务器侧 HTTP 协议错误。

        请求错误若发生在已开始上游通信之后，需要转发给服务器解析器；响应错误
        则通知客户端解析器，并触发 error hook。
        """
        is_client_error_but_we_already_talk_upstream = (
            isinstance(event, RequestProtocolError)
            and self.client_state in (self.state_stream_request_body, self.state_done)
            and self.server_state not in (self.state_done, self.state_errored)
        )
        need_error_hook = not (
            self.client_state == self.state_errored
            or self.server_state in (self.state_done, self.state_errored)
        )

        if is_client_error_but_we_already_talk_upstream:
            yield SendHttp(event, self.context.server)
            self.client_state = self.state_errored

        if need_error_hook:
            # We don't want to trigger both a response hook and an error hook,
            # so we need to check if the response is done yet or not.
            self.flow.error = flow.Error(event.message)
            yield HttpErrorHook(self.flow)

        if (yield from self.check_killed(False)):
            return

        if isinstance(event, ResponseProtocolError):
            if self.client_state != self.state_errored:
                yield SendHttp(event, self.context.client)
            self.server_state = self.state_errored

        self.flow.live = False
        yield DropStream(self.stream_id)

    def make_server_connection(self) -> layer.CommandGenerator[bool]:
        """
        为当前 HTTP 请求获取或建立上游服务器连接。

        普通 HTTP 请求会在这里根据 request 的 host、port 和 scheme 选择
        直连或经 upstream proxy 建连。CONNECT 请求本身不通过这个函数转发；
        CONNECT 是给代理的建隧道指令，由 `handle_connect()` 单独处理。
        """
        connection, err = yield GetHttpConnection(
            (self.flow.request.host, self.flow.request.port),
            self.flow.request.scheme == "https",
            self.flow.server_conn.via,
            self.flow.server_conn.transport_protocol,
        )
        if err:
            yield from self.handle_protocol_error(
                ResponseProtocolError(self.stream_id, err, ErrorCode.CONNECT_FAILED)
            )
            return False
        else:
            self.context.server = self.flow.server_conn = connection
            return True

    def handle_connect(self) -> layer.CommandGenerator[None]:
        """
        处理客户端发来的 HTTP CONNECT 指令。

        手机访问 HTTPS 站点时，系统 HTTP 代理会先发 CONNECT。mitmproxy 在
        这里把 CONNECT 的 host/port 记录为目标服务器地址，触发
        `HttpConnectHook` 允许 addon 干预，然后根据当前 HTTP mode 选择直接
        建隧道或通过 upstream proxy 建隧道。
        """
        self.client_state = self.state_done
        yield HttpConnectHook(self.flow)
        if (yield from self.check_killed(False)):
            return

        self.context.server.address = (self.flow.request.host, self.flow.request.port)

        if self.mode == HTTPMode.regular:
            yield from self.handle_connect_regular()
        else:
            yield from self.handle_connect_upstream()

    def handle_connect_regular(self):
        """
        在 regular 模式下完成 CONNECT 的服务器侧准备。

        如果配置为 eager 连接策略，会先尝试连接目标服务器，以便早发现错误。
        随后创建 `NextLayer` 作为隧道内协议解析入口：手机收到 200 后通常会
        在同一连接里继续发送 TLS ClientHello，后续由 `NextLayer` 识别为
        TLS layer。
        """
        if (
            not self.flow.response
            and self.context.options.connection_strategy == "eager"
        ):
            err = yield commands.OpenConnection(self.context.server)
            if err:
                self.flow.response = http.Response.make(
                    502,
                    f"Cannot connect to {human.format_address(self.context.server.address)}: {err} "
                    f"If you plan to redirect requests away from this server, "
                    f"consider setting `connection_strategy` to `lazy` to suppress early connections.",
                )
        self.child_layer = layer.NextLayer(self.context)
        yield from self.handle_connect_finish()

    def handle_connect_upstream(self):
        """
        在 upstream 模式下通过上游 HTTP(S) 代理建立 CONNECT 隧道。
        """
        self.child_layer = _upstream_proxy.HttpUpstreamProxy.make(self.context, True)[0]
        yield from self.handle_connect_finish()

    def handle_connect_finish(self):
        """
        完成 CONNECT 响应并切换到隧道透传状态。

        如果没有 addon 提前设置响应，则生成 `200 Connection established`。
        2xx 响应表示隧道成立，当前 HTTP stream 后续进入 `passthrough`，
        客户端后续字节交给 child layer 继续解析；非 2xx 响应则认为
        CONNECT 失败，不进入隧道。
        """
        if not self.flow.response:
            # Do not send any response headers as it breaks proxying non-80 ports on
            # Android emulators using the -http-proxy option.
            # 不发送额外响应头是为了兼容 Android 模拟器的 -http-proxy 选项；
            # 某些非 80 端口代理场景会因为额外头字段而失败。
            self.flow.response = http.Response(
                self.flow.request.data.http_version,
                200,
                b"Connection established",
                http.Headers(),
                b"",
                None,
                time.time(),
                time.time(),
            )

        if 200 <= self.flow.response.status_code < 300:
            yield HttpConnectedHook(self.flow)
            self.child_layer = self.child_layer or layer.NextLayer(self.context)
            self._handle_event = self.passthrough
            yield from self.child_layer.handle_event(events.Start())
        else:
            yield HttpConnectErrorHook(self.flow)
            self.client_state = self.state_errored
            self.flow.live = False

        content = self.flow.response.raw_content
        done_after_headers = not (content or self.flow.response.trailers)
        yield SendHttp(
            ResponseHeaders(self.stream_id, self.flow.response, done_after_headers),
            self.context.client,
        )
        if content:
            yield SendHttp(ResponseData(self.stream_id, content), self.context.client)

        if self.flow.response.trailers:
            yield SendHttp(
                ResponseTrailers(self.stream_id, self.flow.response.trailers),
                self.context.client,
            )
        yield SendHttp(ResponseEndOfMessage(self.stream_id), self.context.client)

    @expect(RequestData, RequestEndOfMessage, events.Event)
    def passthrough(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        隧道/升级后的透传桥接。

        CONNECT 成功或 HTTP 101 升级后，HTTP 事件会被转换成普通连接事件交给
        child layer；child layer 发出的连接命令再被包装回 HTTP event。
        """
        assert self.flow.response
        assert self.child_layer
        # HTTP events -> normal connection events
        if isinstance(event, RequestData):
            event = events.DataReceived(self.context.client, event.data)
        elif isinstance(event, ResponseData):
            event = events.DataReceived(self.context.server, event.data)
        elif isinstance(event, RequestEndOfMessage):
            event = events.ConnectionClosed(self.context.client)
        elif isinstance(event, ResponseEndOfMessage):
            event = events.ConnectionClosed(self.context.server)

        for command in self.child_layer.handle_event(event):
            # normal connection events -> HTTP events
            if isinstance(command, commands.SendData):
                if command.connection == self.context.client:
                    yield SendHttp(
                        ResponseData(self.stream_id, command.data), self.context.client
                    )
                elif (
                    command.connection == self.context.server
                    and self.flow.response.status_code == 101
                ):
                    # there only is a HTTP server connection if we have switched protocols,
                    # not if a connection is established via CONNECT.
                    yield SendHttp(
                        RequestData(self.stream_id, command.data), self.context.server
                    )
                else:
                    yield command
            elif isinstance(command, commands.CloseConnection):
                if command.connection == self.context.client:
                    yield SendHttp(
                        ResponseProtocolError(
                            self.stream_id, "EOF", ErrorCode.PASSTHROUGH_CLOSE
                        ),
                        self.context.client,
                    )
                elif (
                    command.connection == self.context.server
                    and self.flow.response.status_code == 101
                ):
                    yield SendHttp(
                        RequestProtocolError(
                            self.stream_id, "EOF", ErrorCode.PASSTHROUGH_CLOSE
                        ),
                        self.context.server,
                    )
                else:
                    # If we are running TCP over HTTP we want to be consistent with half-closes.
                    # The easiest approach for this is to just always full close for now.
                    # Alternatively, we could signal that we want a half close only through ResponseProtocolError,
                    # but that is more complex to implement.
                    if isinstance(command, commands.CloseTcpConnection):
                        command = commands.CloseConnection(command.connection)
                    yield command
            else:
                yield command

    @expect()
    def state_uninitialized(self, _) -> layer.CommandGenerator[None]:
        """初始空状态，等待 `events.Start` 激活。"""
        yield from ()

    @expect()
    def state_done(self, _) -> layer.CommandGenerator[None]:
        """已完成状态，静默忽略后续事件。"""
        yield from ()

    def state_errored(self, _) -> layer.CommandGenerator[None]:
        """错误状态，静默消费后续事件以保持状态机稳定。"""
        # silently consume every event.
        yield from ()


class HttpLayer(layer.Layer):
    """
    ConnectionEvent: We have received b"GET /\r\n\r\n" from the client.
    HttpEvent: We have received request headers
    HttpCommand: Send request headers to X
    ConnectionCommand: Send b"GET /\r\n\r\n" to server.

    ConnectionEvent -> HttpEvent -> HttpCommand -> ConnectionCommand

    中文说明：连接级 HTTP layer，负责把底层连接事件交给 HTTP/1/2/3
    解析器，把解析出的 `ReceiveHttp` 路由到对应 `HttpStream`，并处理
    stream 发出的连接申请、发送、丢弃等命令。
    """

    mode: HTTPMode
    command_sources: dict[commands.Command, layer.Layer]
    streams: dict[int, HttpStream]
    connections: dict[Connection, layer.Layer]
    waiting_for_establishment: collections.defaultdict[
        Connection, list[GetHttpConnection]
    ]

    def __init__(self, context: Context, mode: HTTPMode):
        """
        初始化连接表、stream 表和阻塞命令来源表。

        `waiting_for_establishment` 记录等待同一服务器连接建立的多个 stream，
        连接成功/失败后会统一回调。
        """
        super().__init__(context)
        self.mode = mode

        self.waiting_for_establishment = collections.defaultdict(list)
        self.streams = {}
        self.command_sources = {}
        self.connections = {}

    def __repr__(self):
        return f"HttpLayer({self.mode.name}, conns: {len(self.connections)})"

    def _handle_event(self, event: events.Event):
        """
        HttpLayer 总入口：根据事件类型路由到客户端/服务器 HTTP 解析器或 stream。
        """
        if isinstance(event, events.Start):
            http_conn: HttpConnection
            if is_h3_alpn(self.context.client.alpn):
                http_conn = Http3Server(self.context.fork())
            elif self.context.client.alpn == b"h2":
                http_conn = Http2Server(self.context.fork())
            else:
                http_conn = Http1Server(self.context.fork())

            # may have been set by client playback.
            self.connections.setdefault(self.context.client, http_conn)
            yield from self.event_to_child(self.connections[self.context.client], event)
            if self.mode is HTTPMode.upstream:
                proxy_mode = self.context.client.proxy_mode
                assert isinstance(proxy_mode, UpstreamMode)
                self.context.server.via = (proxy_mode.scheme, proxy_mode.address)
        elif isinstance(event, events.CommandCompleted):
            stream = self.command_sources.pop(event.command)
            yield from self.event_to_child(stream, event)
        elif isinstance(event, events.MessageInjected):
            # For injected messages we pass the HTTP stacks entirely and directly address the stream.
            try:
                conn = self.connections[event.flow.server_conn]
            except KeyError:
                # We have a miss for the server connection, which means we're looking at a connection object
                # that is tunneled over another connection (for example: over an upstream HTTP proxy).
                # We now take the stream associated with the client connection. That won't work for HTTP/2,
                # but it's good enough for HTTP/1.
                conn = self.connections[event.flow.client_conn]
            if isinstance(conn, HttpStream):
                stream_id = conn.stream_id
            else:
                # We reach to the end of the connection's child stack to get the HTTP/1 client layer,
                # which tells us which stream we are dealing with.
                conn = conn.context.layers[-1]
                assert isinstance(conn, Http1Connection)
                assert conn.stream_id
                stream_id = conn.stream_id
            yield from self.event_to_child(self.streams[stream_id], event)
        elif isinstance(event, events.ConnectionEvent):
            if (
                event.connection == self.context.server
                and self.context.server not in self.connections
            ):
                # We didn't do anything with this connection yet, now the peer is doing something.
                if isinstance(event, events.ConnectionClosed):
                    # The peer has closed it - let's close it too!
                    yield commands.CloseConnection(event.connection)
                elif isinstance(event, (events.DataReceived, QuicStreamEvent)):
                    # The peer has sent data or another connection activity occurred.
                    # This can happen with HTTP/2 servers that already send a settings frame.
                    child_layer: HttpConnection
                    if is_h3_alpn(self.context.server.alpn):
                        child_layer = Http3Client(self.context.fork())
                    elif self.context.server.alpn == b"h2":
                        child_layer = Http2Client(self.context.fork())
                    else:
                        child_layer = Http1Client(self.context.fork())
                    self.connections[self.context.server] = child_layer
                    yield from self.event_to_child(child_layer, events.Start())
                    yield from self.event_to_child(child_layer, event)
                else:
                    raise AssertionError(f"Unexpected event: {event}")
            else:
                handler = self.connections[event.connection]
                yield from self.event_to_child(handler, event)
        else:
            raise AssertionError(f"Unexpected event: {event}")

    def event_to_child(
        self,
        child: layer.Layer | HttpStream,
        event: events.Event,
    ) -> layer.CommandGenerator[None]:
        """
        把事件送入子 layer，并解释子 layer 产出的命令。

        这里是 HTTP 层的路由枢纽：
        - HTTP 解析器产出 `ReceiveHttp` 时，创建/查找对应 `HttpStream`。
        - stream 产出 `SendHttp` 时，回送给目标连接解析器。
        - 阻塞命令会登记来源，以便 `CommandCompleted` 能回到正确 stream。
        """
        for command in child.handle_event(event):
            assert isinstance(command, commands.Command)
            # Streams may yield blocking commands, which ultimately generate CommandCompleted events.
            # Those need to be routed back to the correct stream, so we need to keep track of that.

            if command.blocking or isinstance(command, commands.RequestWakeup):
                self.command_sources[command] = child

            if isinstance(command, ReceiveHttp):
                if isinstance(command.event, RequestHeaders):
                    yield from self.make_stream(command.event.stream_id)
                try:
                    stream = self.streams[command.event.stream_id]
                except KeyError:
                    # We may be getting data or errors for a stream even though we've already finished handling it,
                    # see for example https://github.com/mitmproxy/mitmproxy/issues/5343.
                    pass
                else:
                    yield from self.event_to_child(stream, command.event)
            elif isinstance(command, SendHttp):
                conn = self.connections[command.connection]
                yield from self.event_to_child(conn, command.event)
            elif isinstance(command, DropStream):
                self.streams.pop(command.stream_id, None)
            elif isinstance(command, GetHttpConnection):
                yield from self.get_connection(command)
            elif isinstance(command, RegisterHttpConnection):
                yield from self.register_connection(command)
            elif isinstance(command, commands.OpenConnection):
                self.connections[command.connection] = child
                yield command
            elif isinstance(command, commands.Command):
                yield command
            else:
                raise AssertionError(f"Not a command: {event}")

    def make_stream(self, stream_id: int) -> layer.CommandGenerator[None]:
        """
        为新的 HTTP stream 创建 `HttpStream` 状态机。

        触发点：HTTP/1/2/3 解析器第一次产出对应 stream_id 的 RequestHeaders。
        """
        ctx = self.context.fork()
        self.streams[stream_id] = HttpStream(ctx, stream_id)
        yield from self.event_to_child(self.streams[stream_id], events.Start())

    def get_connection(
        self, event: GetHttpConnection, *, reuse: bool = True
    ) -> layer.CommandGenerator[None]:
        """
        为 stream 获取可用上游 HTTP 连接。

        优先复用满足目标地址、TLS、上游代理、传输协议条件的连接；没有可复用连接
        时，根据 upstream/tls/quic 等需求搭建隧道栈并启动连接建立流程。
        """
        # Do we already have a connection we can re-use?
        if reuse:
            for connection in self.connections:
                connection_suitable = event.connection_spec_matches(connection)
                if connection_suitable:
                    if connection in self.waiting_for_establishment:
                        self.waiting_for_establishment[connection].append(event)
                        return
                    elif connection.error:
                        stream = self.command_sources.pop(event)
                        yield from self.event_to_child(
                            stream,
                            GetHttpConnectionCompleted(event, (None, connection.error)),
                        )
                        return
                    elif connection.connected:
                        # see "tricky multiplexing edge case" in make_http_connection for an explanation
                        h2_to_h1 = (
                            self.context.client.alpn == b"h2"
                            and connection.alpn != b"h2"
                        )
                        if not h2_to_h1:
                            stream = self.command_sources.pop(event)
                            yield from self.event_to_child(
                                stream,
                                GetHttpConnectionCompleted(event, (connection, None)),
                            )
                            return
                    else:
                        pass  # the connection is at least half-closed already, we want a new one.

        context_connection_matches = (
            self.context.server not in self.connections
            and event.connection_spec_matches(self.context.server)
        )
        can_use_context_connection = (
            context_connection_matches and self.context.server.connected
        )
        if context_connection_matches and self.context.server.error:
            stream = self.command_sources.pop(event)
            yield from self.event_to_child(
                stream,
                GetHttpConnectionCompleted(event, (None, self.context.server.error)),
            )
            return

        context = self.context.fork()

        stack = tunnel.LayerStack()

        if not can_use_context_connection:
            context.server = Server(
                address=event.address, transport_protocol=event.transport_protocol
            )

            if event.via:
                context.server.via = event.via
                # We always send a CONNECT request, *except* for plaintext absolute-form HTTP requests in upstream mode.
                send_connect = event.tls or self.mode != HTTPMode.upstream
                stack /= _upstream_proxy.HttpUpstreamProxy.make(context, send_connect)
            if event.tls:
                # Assume that we are in transparent mode and lazily did not open a connection yet.
                # We don't want the IP (which is the address) as the upstream SNI, but the client's SNI instead.
                if (
                    self.mode == HTTPMode.transparent
                    and event.address == self.context.server.address
                ):
                    # reverse proxy mode may set self.context.server.sni, which takes precedence.
                    context.server.sni = (
                        self.context.server.sni
                        or self.context.client.sni
                        or event.address[0]
                    )
                else:
                    context.server.sni = event.address[0]
                if context.server.transport_protocol == "tcp":
                    stack /= tls.ServerTLSLayer(context)
                elif context.server.transport_protocol == "udp":
                    stack /= quic.ServerQuicLayer(context)
                else:
                    raise AssertionError(
                        context.server.transport_protocol
                    )  # pragma: no cover

        stack /= HttpClient(context)

        self.connections[context.server] = stack[0]
        self.waiting_for_establishment[context.server].append(event)

        yield from self.event_to_child(stack[0], events.Start())

    def register_connection(
        self, command: RegisterHttpConnection
    ) -> layer.CommandGenerator[None]:
        """
        连接建立完成后的回调分发。

        同一服务器连接建立期间可能有多个 stream 在等待，结果会广播给所有等待者。
        """
        waiting = self.waiting_for_establishment.pop(command.connection)

        reply: tuple[None, str] | tuple[Connection, None]
        if command.err:
            reply = (None, command.err)
        else:
            reply = (command.connection, None)

        for cmd in waiting:
            stream = self.command_sources.pop(cmd)
            yield from self.event_to_child(
                stream, GetHttpConnectionCompleted(cmd, reply)
            )

            # Tricky multiplexing edge case: Assume we are doing HTTP/2 -> HTTP/1 proxying and the destination server
            # only serves responses with HTTP read-until-EOF semantics. In this case we can't process two flows on the
            # same connection. The only workaround left is to open a separate connection for each flow.
            if (
                not command.err
                and self.context.client.alpn == b"h2"
                and command.connection.alpn != b"h2"
            ):
                for cmd in waiting[1:]:
                    yield from self.get_connection(cmd, reuse=False)
                break


class HttpClient(layer.Layer):
    """
    出站 HTTP 客户端连接启动器。

    `HttpLayer.get_connection()` 创建连接栈后，最末端使用本 layer 打开 TCP/QUIC
    连接，并按 ALPN 选择 HTTP/1、HTTP/2 或 HTTP/3 客户端解析器。
    """

    child_layer: layer.Layer

    @expect(events.Start)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        """
        打开服务器连接并注册连接建立结果。
        """
        err: str | None
        if self.context.server.connected:
            err = None
        else:
            err = yield commands.OpenConnection(self.context.server)
        if not err:
            if is_h3_alpn(self.context.server.alpn):
                self.child_layer = Http3Client(self.context)
            elif self.context.server.alpn == b"h2":
                self.child_layer = Http2Client(self.context)
            else:
                self.child_layer = Http1Client(self.context)
            self._handle_event = self.child_layer.handle_event
            yield from self._handle_event(event)
        yield RegisterHttpConnection(self.context.server, err)
