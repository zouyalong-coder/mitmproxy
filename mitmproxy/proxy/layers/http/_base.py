"""
HTTP layer 的基础事件、命令和工具函数。

HTTP/1、HTTP/2、HTTP/3 解析器都会把协议细节转换为这里定义的 `HttpEvent`，
再交给上层 `HttpStream` 状态机统一处理。
"""

import html
import textwrap
from dataclasses import dataclass

from mitmproxy import http
from mitmproxy.connection import Connection
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy.context import Context

StreamId = int


@dataclass
class HttpEvent(events.Event):
    """
    HTTP 子事件基类。

    每个事件都带 `stream_id`，这样多路复用协议（HTTP/2/3）可以并发处理多个
    请求/响应流，HTTP/1 则通常使用固定流 ID。
    """

    # we need stream ids on every event to avoid race conditions
    stream_id: StreamId


class HttpConnection(layer.Layer):
    """
    HTTP 连接解析器基类，绑定一个具体客户端或服务端 Connection。
    """

    conn: Connection

    def __init__(self, context: Context, conn: Connection):
        """
        初始化 HTTP 连接层并记录对应连接对象。
        """
        super().__init__(context)
        self.conn = conn


class HttpCommand(commands.Command):
    """
    HTTP layer 内部命令基类。
    """

    pass


class ReceiveHttp(HttpCommand):
    """
    把底层 HTTP 解析器产生的 HttpEvent 送回 HttpLayer/HttpStream。
    """

    event: HttpEvent

    def __init__(self, event: HttpEvent):
        """
        保存要向上分发的 HTTP 事件。
        """
        self.event = event

    def __repr__(self) -> str:
        return f"Receive({self.event})"


def format_error(status_code: int, message: str) -> bytes:
    """
    生成简单 HTML 错误页，用于协议错误或代理自身错误响应。
    """
    reason = http.status_codes.RESPONSES.get(status_code, "Unknown")
    return (
        textwrap.dedent(
            f"""
    <html>
    <head>
        <title>{status_code} {reason}</title>
    </head>
    <body>
        <h1>{status_code} {reason}</h1>
        <p>{html.escape(message)}</p>
    </body>
    </html>
    """
        )
        .strip()
        .encode("utf8", "replace")
    )
