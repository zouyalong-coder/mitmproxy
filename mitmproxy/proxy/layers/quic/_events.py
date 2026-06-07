"""
QUIC layer 向上层派发的连接/stream 事件。

这些事件由 `QuicLayer` 解析 UDP datagram 后产生，供 HTTP/3、raw QUIC stream
或其他子 layer 消费。它们对应 QUIC stream data、reset、stop sending，以及
连接关闭等协议事件。
"""

from __future__ import annotations

from dataclasses import dataclass

from mitmproxy import connection
from mitmproxy.proxy import events


@dataclass
class QuicStreamEvent(events.ConnectionEvent):
    """
    Base class for all QUIC stream events.

    中文说明：所有 QUIC stream 事件都带有底层连接对象和 stream_id。
    """

    stream_id: int
    """The ID of the stream the event was fired for."""


@dataclass
class QuicStreamDataReceived(QuicStreamEvent):
    """
    Event that is fired whenever data is received on a stream.

    中文说明：QUIC STREAM frame 到达时触发，`end_stream` 对应 FIN。
    """

    data: bytes
    """The data which was received."""
    end_stream: bool
    """Whether the STREAM frame had the FIN bit set."""

    def __repr__(self):
        target = repr(self.connection).partition("(")[0].lower()
        end_stream = "[end_stream] " if self.end_stream else ""
        return f"QuicStreamDataReceived({target} on {self.stream_id}, {end_stream}{self.data!r})"


@dataclass
class QuicStreamReset(QuicStreamEvent):
    """
    Event that is fired when the remote peer resets a stream.

    中文说明：远端发送 RESET_STREAM 时触发。
    """

    error_code: int
    """The error code that triggered the reset."""


@dataclass
class QuicStreamStopSending(QuicStreamEvent):
    """
    Event that is fired when the remote peer sends a STOP_SENDING frame.

    中文说明：远端请求本端停止发送某个 stream 时触发。
    """

    error_code: int
    """The application protocol error code."""


class QuicConnectionClosed(events.ConnectionClosed):
    """
    QUIC connection has been closed.

    中文说明：QUIC CONNECTION_CLOSE 或传输关闭后触发，携带错误码和原因。
    """

    error_code: int
    "The error code which was specified when closing the connection."

    frame_type: int | None
    "The frame type which caused the connection to be closed, or `None`."

    reason_phrase: str
    "The human-readable reason for which the connection was closed."

    def __init__(
        self,
        conn: connection.Connection,
        error_code: int,
        frame_type: int | None,
        reason_phrase: str,
    ) -> None:
        super().__init__(conn)
        self.error_code = error_code
        self.frame_type = frame_type
        self.reason_phrase = reason_phrase
