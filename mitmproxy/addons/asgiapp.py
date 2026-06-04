"""
在 mitmproxy 内托管 ASGI/WSGI 应用的 addon 基类。

触发点：
- `request`：每个 HTTP 请求发往上游前触发；如果 host/port 匹配本应用，
  则直接调用 ASGI 应用并把返回值写入 `flow.response`。
- `receive`/`send`：不是 mitmproxy hook，而是 ASGI 应用调用的协议回调。
"""

import asyncio
import logging
import urllib.parse

import asgiref.compatibility
import asgiref.wsgi

from mitmproxy import ctx
from mitmproxy import http

logger = logging.getLogger(__name__)


class ASGIApp:
    """
    An addon that hosts an ASGI/WSGI HTTP app within mitmproxy, at a specified hostname and port.

    Some important caveats:
        - This implementation will block and wait until the entire HTTP response is completed before sending out data.
        - It currently only implements the HTTP protocol (Lifespan and WebSocket are unimplemented).
    
    中文说明：这个 addon 把某个 host/port 绑定到本地 Python Web 应用。
    命中后会短路代理转发，不再访问上游服务器。
    """

    def __init__(self, asgi_app, host: str, port: int | None):
        """
        初始化托管应用和匹配的 host/port。
        """
        asgi_app = asgiref.compatibility.guarantee_single_callable(asgi_app)
        self.asgi_app, self.host, self.port = asgi_app, host, port

    @property
    def name(self) -> str:
        """
        返回 addon 名称，用 host/port 区分多个托管应用。
        """
        return f"asgiapp:{self.host}:{self.port}"

    def should_serve(self, flow: http.HTTPFlow) -> bool:
        """
        根据当前配置和 flow 状态判断是否应执行后续处理。
        """
        return bool(
            flow.request.pretty_host == self.host
            and (self.port is None or flow.request.port == self.port)
            and flow.live
            and not flow.error
            and not flow.response
        )

    async def request(self, flow: http.HTTPFlow) -> None:
        """
        HTTP `request` 事件：请求发往上游前触发。

        如果 `should_serve()` 命中，就调用本地 ASGI 应用生成响应。
        """
        if self.should_serve(flow):
            await serve(self.asgi_app, flow)


class WSGIApp(ASGIApp):
    """
    WSGI 应用适配器。

    通过 `asgiref.wsgi.WsgiToAsgi` 把 WSGI 应用包装为 ASGI，再复用
    `ASGIApp` 的 request hook。
    """

    def __init__(self, wsgi_app, host: str, port: int | None):
        """
        初始化 WSGI 应用并转换为 ASGI callable。
        """
        asgi_app = asgiref.wsgi.WsgiToAsgi(wsgi_app)
        super().__init__(asgi_app, host, port)


HTTP_VERSION_MAP = {
    "HTTP/1.0": "1.0",
    "HTTP/1.1": "1.1",
    "HTTP/2.0": "2",
}


def make_scope(flow: http.HTTPFlow) -> dict:
    # %3F is a quoted question mark
    """
    把 mitmproxy 的 HTTPFlow 转换为 ASGI/WSGI 应用所需的 scope/environ 元数据。
    """
    quoted_path = urllib.parse.quote_from_bytes(flow.request.data.path).split(
        "%3F", maxsplit=1
    )

    # (Unicode string) – HTTP request target excluding any query string, with percent-encoded
    # sequences and UTF-8 byte sequences decoded into characters.
    path = quoted_path[0]

    # (byte string) – URL portion after the ?, percent-encoded.
    query_string: bytes
    if len(quoted_path) > 1:
        query_string = urllib.parse.unquote(quoted_path[1]).encode()
    else:
        query_string = b""

    return {
        "type": "http",
        "asgi": {
            "version": "3.0",
            "spec_version": "2.1",
        },
        "http_version": HTTP_VERSION_MAP.get(flow.request.http_version, "1.1"),
        "method": flow.request.method,
        "scheme": flow.request.scheme.upper(),
        "path": path,
        "raw_path": flow.request.path,
        "query_string": query_string,
        "headers": [
            (name.lower(), value) for (name, value) in flow.request.headers.fields
        ],
        "client": flow.client_conn.peername,
        "extensions": {
            "mitmproxy.master": ctx.master,
        },
    }


async def serve(app, flow: http.HTTPFlow):
    """
    Serves app on flow.
    
    中文说明：这是 ASGI 执行入口，由 `ASGIApp.request()` 在 host/port 命中时
    调用。它把 flow 转成 scope，并用 receive/send 回调在 ASGI 协议和
    `flow.response` 之间搬运数据。
    """

    scope = make_scope(flow)
    done = asyncio.Event()
    received_body = False
    sent_response = False

    async def receive():
        """
        ASGI `receive` 回调：应用拉取请求体时触发。

        mitmproxy 已经把请求体放在 `flow.request.raw_content` 中，所以这里第一
        次返回完整 body，后续等待请求结束并返回 disconnect。
        """
        nonlocal received_body
        if not received_body:
            received_body = True
            return {
                "type": "http.request",
                "body": flow.request.raw_content,
            }
        else:  # pragma: no cover
            # We really don't expect this to be called a second time, but what to do?
            # We just wait until the request is done before we continue here with sending a disconnect.
            await done.wait()
            return {"type": "http.disconnect"}

    async def send(event):
        """
        ASGI `send` 回调：应用发送响应头或响应体时触发。

        `http.response.start` 创建 `flow.response`，`http.response.body`
        逐段追加响应体。
        """
        if event["type"] == "http.response.start":
            flow.response = http.Response.make(
                event["status"], b"", event.get("headers", [])
            )
            flow.response.decode()
        elif event["type"] == "http.response.body":
            assert flow.response
            flow.response.content += event.get("body", b"")
            if not event.get("more_body", False):
                nonlocal sent_response
                sent_response = True
        else:
            raise AssertionError(f"Unexpected event: {event['type']}")

    try:
        await app(scope, receive, send)
        if not sent_response:
            raise RuntimeError(f"no response sent.")
    except Exception as e:
        logger.exception(f"Error in asgi app: {e}")
        flow.response = http.Response.make(500, b"ASGI Error.")
    finally:
        done.set()
