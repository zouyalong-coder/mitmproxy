from dataclasses import dataclass

from mitmproxy import http
from mitmproxy.proxy import commands


@dataclass
class HttpRequestHeadersHook(commands.StartHook):
    """
    HTTP request headers were successfully read. At this point, the body is empty.
    """

    name = "requestheaders"
    flow: http.HTTPFlow


@dataclass
class HttpRequestHook(commands.StartHook):
    """
    The full HTTP request has been read.

    Note: If request streaming is active, this event fires after the entire body has been streamed.
    HTTP trailers, if present, have not been transmitted to the server yet and can still be modified.
    Enabling streaming may cause unexpected event sequences: For example, `response` may now occur
    before `request` because the server replied with "413 Payload Too Large" during upload.
    """

    name = "request"
    flow: http.HTTPFlow


@dataclass
class HttpResponseHeadersHook(commands.StartHook):
    """
    HTTP response headers were successfully read. At this point, the body is empty.
    """

    name = "responseheaders"
    flow: http.HTTPFlow


@dataclass
class HttpResponseHook(commands.StartHook):
    """
    The full HTTP response has been read.

    Note: If response streaming is active, this event fires after the entire body has been streamed.
    HTTP trailers, if present, have not been transmitted to the client yet and can still be modified.
    """

    name = "response"
    flow: http.HTTPFlow


@dataclass
class HttpErrorHook(commands.StartHook):
    """
    An HTTP error has occurred, e.g. invalid server responses, or
    interrupted connections. This is distinct from a valid server HTTP
    error response, which is simply a response with an HTTP error code.

    Every flow will receive either an error or an response event, but not both.
    """

    name = "error"
    flow: http.HTTPFlow


@dataclass
class HttpConnectHook(commands.StartHook):
    """
    An HTTP CONNECT request was received. This event can be ignored for most practical purposes.

    This event only occurs in regular and upstream proxy modes
    when the client instructs mitmproxy to open a connection to an upstream host.
    Setting a non 2xx response on the flow will return the response to the client and abort the connection.

    CONNECT requests are HTTP proxy instructions for mitmproxy itself
    and not forwarded. They do not generate the usual HTTP handler events,
    but all requests going over the newly opened connection will.

    收到客户端发来的 HTTP CONNECT 请求。

    手机访问 HTTPS 站点时，系统 HTTP 代理会先发送
    `CONNECT host:443 HTTP/1.1` 给 mitmproxy。这个 CONNECT 是给代理本身
    的指令，不会作为普通 HTTP 请求转发；CONNECT 建立后的隧道内请求才会
    继续触发常规 request/response hook。
    """

    flow: http.HTTPFlow


@dataclass
class HttpConnectUpstreamHook(commands.StartHook):
    """
    An HTTP CONNECT request is about to be sent to an upstream proxy.
    This event can be ignored for most practical purposes.

    This event can be used to set custom authentication headers for upstream proxies.

    CONNECT requests do not generate the usual HTTP handler events,
    but all requests going over the newly opened connection will.
    """

    flow: http.HTTPFlow


@dataclass
class HttpConnectedHook(commands.StartHook):
    """
    HTTP CONNECT was successful

    > [!WARNING]
    > This may fire before an upstream connection has been established
    > if `connection_strategy` is set to `lazy` (default)

    HTTP CONNECT 已经成功。

    对手机代理场景来说，这通常意味着 mitmproxy 已经向手机返回 2xx 响应，
    后续该 TCP 连接会切换成隧道模式，里面通常继续进行 TLS 握手。
    """

    flow: http.HTTPFlow


@dataclass
class HttpConnectErrorHook(commands.StartHook):
    """
    HTTP CONNECT has failed.
    This can happen when the upstream server is unreachable or proxy authentication is required.
    In contrast to the `error` hook, `flow.error` is not guaranteed to be set.

    HTTP CONNECT 失败。

    例如目标服务器不可达、上游代理拒绝连接，或者代理认证失败。此时不会
    进入 CONNECT 隧道，客户端会收到错误响应。
    """

    flow: http.HTTPFlow
