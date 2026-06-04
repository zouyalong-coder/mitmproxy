"""
Mitmproxy used to have its own WebSocketFlow type until mitmproxy 6, but now WebSocket connections now are represented
as HTTP flows as well. They can be distinguished from regular HTTP requests by having the
`mitmproxy.http.HTTPFlow.websocket` attribute set.

This module only defines the classes for individual `WebSocketMessage`s and the `WebSocketData` container.

中文说明：mitmproxy 现在把 WebSocket 作为 HTTP 升级后的附属数据保存，一条
WebSocket 连接会出现在 `HTTPFlow.websocket` 上。本模块只负责保存消息列表、
关闭信息和单条消息的方向/类型/内容，不负责协议握手本身。
"""

import time
import warnings
from dataclasses import dataclass
from dataclasses import field

from wsproto.frame_protocol import Opcode

from mitmproxy.coretypes import serializable

WebSocketMessageState = tuple[int, bool, bytes, float, bool, bool]


class WebSocketMessage(serializable.Serializable):
    """
    A single WebSocket message sent from one peer to the other.

    Fragmented WebSocket messages are reassembled by mitmproxy and then
    represented as a single instance of this class.

    The [WebSocket RFC](https://tools.ietf.org/html/rfc6455) specifies both
    text and binary messages. To avoid a whole class of nasty type confusion bugs,
    mitmproxy stores all message contents as `bytes`. If you need a `str`, you can access the `text` property
    on text messages:

    >>> if message.is_text:
    >>>     text = message.text

    中文说明：WebSocket 文本帧和二进制帧最终都以 bytes 保存，避免脚本在
    不知道真实编码时误把二进制当字符串处理。只有 `is_text` 为真时才应使用
    `text` 属性。
    """

    from_client: bool
    """True if this messages was sent by the client."""
    type: Opcode
    """
    The message type, as per RFC 6455's [opcode](https://tools.ietf.org/html/rfc6455#section-5.2).

    Mitmproxy currently only exposes messages assembled from `TEXT` and `BINARY` frames.
    """
    content: bytes
    """A byte-string representing the content of this message."""
    timestamp: float
    """Timestamp of when this message was received or created."""
    dropped: bool
    """True if the message has not been forwarded by mitmproxy, False otherwise."""
    injected: bool
    """True if the message was injected and did not originate from a client/server, False otherwise"""

    def __init__(
        self,
        type: int | Opcode,
        from_client: bool,
        content: bytes,
        timestamp: float | None = None,
        dropped: bool = False,
        injected: bool = False,
    ) -> None:
        """
        创建一条 WebSocket 消息记录。

        `dropped` 表示消息被代理拦下不再转发；`injected` 表示消息由 mitmproxy
        或 addon 注入，不是客户端/服务端真实发出的原始消息。
        """
        self.from_client = from_client
        self.type = Opcode(type)
        self.content = content
        self.timestamp: float = timestamp or time.time()
        self.dropped = dropped
        self.injected = injected

    @classmethod
    def from_state(cls, state: WebSocketMessageState):
        return cls(*state)

    def get_state(self) -> WebSocketMessageState:
        return (
            int(self.type),
            self.from_client,
            self.content,
            self.timestamp,
            self.dropped,
            self.injected,
        )

    def set_state(self, state: WebSocketMessageState) -> None:
        (
            typ,
            self.from_client,
            self.content,
            self.timestamp,
            self.dropped,
            self.injected,
        ) = state
        self.type = Opcode(typ)

    def _format_ws_message(self) -> bytes:
        if self.from_client:
            return b"[OUTGOING] " + self.content
        else:
            return b"[INCOMING] " + self.content

    def __repr__(self):
        if self.type == Opcode.TEXT:
            return repr(self.content.decode(errors="replace"))
        else:
            return repr(self.content)

    @property
    def is_text(self) -> bool:
        """
        `True` if this message is assembled from WebSocket `TEXT` frames,
        `False` if it is assembled from `BINARY` frames.
        """
        return self.type == Opcode.TEXT

    def drop(self):
        """Drop this message, i.e. don't forward it to the other peer."""
        self.dropped = True

    def kill(self):  # pragma: no cover
        """A deprecated alias for `.drop()`."""
        warnings.warn(
            "WebSocketMessage.kill() is deprecated, use .drop() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.drop()

    @property
    def text(self) -> str:
        """
        The message content as text.

        This attribute is only available if `WebSocketMessage.is_text` is `True`.

        *See also:* `WebSocketMessage.content`
        """
        if self.type != Opcode.TEXT:
            raise AttributeError(
                f"{self.type.name.title()} WebSocket frames do not have a 'text' attribute."
            )

        return self.content.decode()

    @text.setter
    def text(self, value: str) -> None:
        if self.type != Opcode.TEXT:
            raise AttributeError(
                f"{self.type.name.title()} WebSocket frames do not have a 'text' attribute."
            )

        self.content = value.encode()


@dataclass
class WebSocketData(serializable.SerializableDataclass):
    """
    A data container for everything related to a single WebSocket connection.
    This is typically accessed as `mitmproxy.http.HTTPFlow.websocket`.

    中文说明：它是一次 WebSocket 会话的聚合容器，记录所有重组后的消息以及
    关闭方向、关闭码、关闭原因等收尾信息。
    """

    messages: list[WebSocketMessage] = field(default_factory=list)
    """All `WebSocketMessage`s transferred over this connection."""

    closed_by_client: bool | None = None
    """
    `True` if the client closed the connection,
    `False` if the server closed the connection,
    `None` if the connection is active.
    """
    close_code: int | None = None
    """[Close Code](https://tools.ietf.org/html/rfc6455#section-7.1.5)"""
    close_reason: str | None = None
    """[Close Reason](https://tools.ietf.org/html/rfc6455#section-7.1.6)"""

    timestamp_end: float | None = None
    """*Timestamp:* WebSocket connection closed."""

    def __repr__(self):
        return f"<WebSocketData ({len(self.messages)} messages)>"

    def _get_formatted_messages(self) -> bytes:
        return b"\n".join(m._format_ws_message() for m in self.messages)
