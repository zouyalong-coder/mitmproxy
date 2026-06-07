"""
HTTP layer 内部事件定义。

底层 HTTP/1、HTTP/2、HTTP/3 解析器会把收到的数据转换成这些事件；`HttpStream`
再根据事件更新 `HTTPFlow` 并触发 addon hook。
"""

import enum
import typing
from dataclasses import dataclass

from ._base import HttpEvent
from mitmproxy import http
from mitmproxy.http import HTTPFlow
from mitmproxy.net.http import status_codes


@dataclass
class RequestHeaders(HttpEvent):
    """
    请求头事件：HTTP 请求头已完整解析。
    """

    request: http.Request
    end_stream: bool
    """
    If True, we already know at this point that there is no message body. This is useful for HTTP/2, where it allows
    us to set END_STREAM on headers already (and some servers - Akamai - implicitly expect that).
    In either case, this event will nonetheless be followed by RequestEndOfMessage.
    """
    replay_flow: HTTPFlow | None = None
    """If set, the current request headers belong to a replayed flow, which should be reused."""


@dataclass
class ResponseHeaders(HttpEvent):
    """
    响应头事件：HTTP 响应头已完整解析。
    """

    response: http.Response
    end_stream: bool = False


# explicit constructors below to facilitate type checking in _http1/_http2


@dataclass
class RequestData(HttpEvent):
    """
    请求体数据块事件。
    """

    data: bytes

    def __init__(self, stream_id: int, data: bytes):
        self.stream_id = stream_id
        self.data = data


@dataclass
class ResponseData(HttpEvent):
    """
    响应体数据块事件。
    """

    data: bytes

    def __init__(self, stream_id: int, data: bytes):
        self.stream_id = stream_id
        self.data = data


@dataclass
class RequestTrailers(HttpEvent):
    """
    请求 trailers 事件。
    """

    trailers: http.Headers

    def __init__(self, stream_id: int, trailers: http.Headers):
        self.stream_id = stream_id
        self.trailers = trailers


@dataclass
class ResponseTrailers(HttpEvent):
    """
    响应 trailers 事件。
    """

    trailers: http.Headers

    def __init__(self, stream_id: int, trailers: http.Headers):
        self.stream_id = stream_id
        self.trailers = trailers


@dataclass
class RequestEndOfMessage(HttpEvent):
    """
    请求消息结束事件。
    """

    def __init__(self, stream_id: int):
        self.stream_id = stream_id


@dataclass
class ResponseEndOfMessage(HttpEvent):
    """
    响应消息结束事件。
    """

    def __init__(self, stream_id: int):
        self.stream_id = stream_id


class ErrorCode(enum.Enum):
    """
    HTTP layer 内部错误分类。

    某些错误可以映射成 HTTP 状态码返回客户端，另一些错误只能关闭流或连接。
    """

    GENERIC_CLIENT_ERROR = 1
    GENERIC_SERVER_ERROR = 2
    REQUEST_TOO_LARGE = 3
    RESPONSE_TOO_LARGE = 4
    CONNECT_FAILED = 5
    PASSTHROUGH_CLOSE = 6
    KILL = 7
    HTTP_1_1_REQUIRED = 8
    """Client should fall back to HTTP/1.1 to perform request."""
    DESTINATION_UNKNOWN = 9
    """Proxy does not know where to send request to."""
    CLIENT_DISCONNECTED = 10
    """Client disconnected before receiving entire response."""
    CANCEL = 11
    """Client or server cancelled h2/h3 stream."""
    REQUEST_VALIDATION_FAILED = 12
    RESPONSE_VALIDATION_FAILED = 13

    def http_status_code(self) -> int | None:
        """
        将内部错误码映射为可返回给客户端的 HTTP 状态码。
        """
        match self:
            # Client Errors
            case (
                ErrorCode.GENERIC_CLIENT_ERROR
                | ErrorCode.REQUEST_VALIDATION_FAILED
                | ErrorCode.DESTINATION_UNKNOWN
            ):
                return status_codes.BAD_REQUEST
            case ErrorCode.REQUEST_TOO_LARGE:
                return status_codes.PAYLOAD_TOO_LARGE
            case (
                ErrorCode.CONNECT_FAILED
                | ErrorCode.GENERIC_SERVER_ERROR
                | ErrorCode.RESPONSE_VALIDATION_FAILED
                | ErrorCode.RESPONSE_TOO_LARGE
            ):
                return status_codes.BAD_GATEWAY
            case (
                ErrorCode.PASSTHROUGH_CLOSE
                | ErrorCode.KILL
                | ErrorCode.HTTP_1_1_REQUIRED
                | ErrorCode.CLIENT_DISCONNECTED
                | ErrorCode.CANCEL
            ):
                return None
            case other:  # pragma: no cover
                typing.assert_never(other)


@dataclass
class RequestProtocolError(HttpEvent):
    """
    客户端请求侧协议错误事件。
    """

    message: str
    code: ErrorCode = ErrorCode.GENERIC_CLIENT_ERROR

    def __init__(self, stream_id: int, message: str, code: ErrorCode):
        assert isinstance(code, ErrorCode)
        self.stream_id = stream_id
        self.message = message
        self.code = code


@dataclass
class ResponseProtocolError(HttpEvent):
    """
    上游响应侧协议错误事件。
    """

    message: str
    code: ErrorCode = ErrorCode.GENERIC_SERVER_ERROR

    def __init__(self, stream_id: int, message: str, code: ErrorCode):
        assert isinstance(code, ErrorCode)
        self.stream_id = stream_id
        self.message = message
        self.code = code


__all__ = [
    "ErrorCode",
    "HttpEvent",
    "RequestHeaders",
    "RequestData",
    "RequestEndOfMessage",
    "ResponseHeaders",
    "ResponseData",
    "RequestTrailers",
    "ResponseTrailers",
    "ResponseEndOfMessage",
    "RequestProtocolError",
    "ResponseProtocolError",
]
