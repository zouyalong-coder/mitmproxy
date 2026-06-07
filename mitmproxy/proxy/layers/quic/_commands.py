"""
QUIC layer 可执行的连接/stream 命令。

上层 HTTP/3 或 raw stream layer 不直接操作 aioquic，而是产出这些命令；
`QuicLayer` 接收后再转换为 QUIC STREAM、RESET_STREAM、STOP_SENDING 或
CONNECTION_CLOSE 操作。
"""

from __future__ import annotations

from mitmproxy import connection
from mitmproxy.proxy import commands


class QuicStreamCommand(commands.ConnectionCommand):
    """
    Base class for all QUIC stream commands.

    中文说明：所有 stream 级命令都指定目标连接和 stream_id。
    """

    stream_id: int
    """The ID of the stream the command was issued for."""

    def __init__(self, connection: connection.Connection, stream_id: int) -> None:
        super().__init__(connection)
        self.stream_id = stream_id


class SendQuicStreamData(QuicStreamCommand):
    """
    Command that sends data on a stream.

    中文说明：由上层请求在 QUIC stream 上发送数据，可选择设置 FIN。
    """

    data: bytes
    """The data which should be sent."""
    end_stream: bool
    """Whether the FIN bit should be set in the STREAM frame."""

    def __init__(
        self,
        connection: connection.Connection,
        stream_id: int,
        data: bytes,
        end_stream: bool = False,
    ) -> None:
        super().__init__(connection, stream_id)
        self.data = data
        self.end_stream = end_stream

    def __repr__(self):
        target = repr(self.connection).partition("(")[0].lower()
        end_stream = "[end_stream] " if self.end_stream else ""
        return f"SendQuicStreamData({target} on {self.stream_id}, {end_stream}{self.data!r})"


class ResetQuicStream(QuicStreamCommand):
    """
    Abruptly terminate the sending part of a stream.

    中文说明：发送 RESET_STREAM，强制终止本端发送方向。
    """

    error_code: int
    """An error code indicating why the stream is being reset."""

    def __init__(
        self, connection: connection.Connection, stream_id: int, error_code: int
    ) -> None:
        super().__init__(connection, stream_id)
        self.error_code = error_code


class StopSendingQuicStream(QuicStreamCommand):
    """
    Request termination of the receiving part of a stream.

    中文说明：发送 STOP_SENDING，请求远端停止发送该 stream。
    """

    error_code: int
    """An error code indicating why the stream is being stopped."""

    def __init__(
        self, connection: connection.Connection, stream_id: int, error_code: int
    ) -> None:
        super().__init__(connection, stream_id)
        self.error_code = error_code


class CloseQuicConnection(commands.CloseConnection):
    """
    Close a QUIC connection.

    中文说明：关闭 QUIC 连接，并携带 QUIC 错误码、帧类型和原因短语。
    """

    error_code: int
    "The error code which was specified when closing the connection."

    frame_type: int | None
    "The frame type which caused the connection to be closed, or `None`."

    reason_phrase: str
    "The human-readable reason for which the connection was closed."

    # XXX: A bit much boilerplate right now. Should switch to dataclasses.
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
