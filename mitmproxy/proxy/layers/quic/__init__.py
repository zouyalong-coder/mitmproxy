"""
QUIC layer 包的公共导出入口。

这里集中导出 QUIC client/server layer、raw QUIC layer、stream 命令/事件和
TLS hook 数据类型，供 HTTP/3、代理模式 layer 以及 addon hook 机制引用。
"""

from ._client_hello_parser import quic_parse_client_hello_from_datagrams
from ._commands import CloseQuicConnection
from ._commands import ResetQuicStream
from ._commands import SendQuicStreamData
from ._commands import StopSendingQuicStream
from ._events import QuicConnectionClosed
from ._events import QuicStreamDataReceived
from ._events import QuicStreamEvent
from ._events import QuicStreamReset
from ._events import QuicStreamStopSending
from ._hooks import QuicStartClientHook
from ._hooks import QuicStartServerHook
from ._hooks import QuicTlsData
from ._hooks import QuicTlsSettings
from ._raw_layers import QuicStreamLayer
from ._raw_layers import RawQuicLayer
from ._stream_layers import ClientQuicLayer
from ._stream_layers import error_code_to_str
from ._stream_layers import ServerQuicLayer

__all__ = [
    "quic_parse_client_hello_from_datagrams",
    "CloseQuicConnection",
    "ResetQuicStream",
    "SendQuicStreamData",
    "StopSendingQuicStream",
    "QuicConnectionClosed",
    "QuicStreamDataReceived",
    "QuicStreamEvent",
    "QuicStreamReset",
    "QuicStreamStopSending",
    "QuicStartClientHook",
    "QuicStartServerHook",
    "QuicTlsData",
    "QuicTlsSettings",
    "QuicStreamLayer",
    "RawQuicLayer",
    "ClientQuicLayer",
    "error_code_to_str",
    "ServerQuicLayer",
]
