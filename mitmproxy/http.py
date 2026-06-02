import binascii
import json
import os
import time
import urllib.parse
import warnings
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import fields
from email.utils import formatdate
from email.utils import mktime_tz
from email.utils import parsedate_tz
from typing import Any
from typing import cast

from mitmproxy import flow
from mitmproxy.coretypes import multidict
from mitmproxy.coretypes import serializable
from mitmproxy.net import encoding
from mitmproxy.net.http import cookies
from mitmproxy.net.http import multipart
from mitmproxy.net.http import status_codes
from mitmproxy.net.http import url
from mitmproxy.net.http.headers import assemble_content_type
from mitmproxy.net.http.headers import infer_content_encoding
from mitmproxy.net.http.headers import parse_content_type
from mitmproxy.utils import human
from mitmproxy.utils import strutils
from mitmproxy.utils import typecheck
from mitmproxy.utils.strutils import always_bytes
from mitmproxy.utils.strutils import always_str
from mitmproxy.websocket import WebSocketData


# While headers _should_ be ASCII, it's not uncommon for certain headers to be utf-8 encoded.
def _native(x: bytes) -> str:
    """
    将 HTTP 头字段中的原始字节转换为 Python 字符串。

    HTTP 头理论上应是 ASCII，但真实世界里经常混入 UTF-8。这里使用
    `surrogateescape` 保留不可正常解码的字节，避免在展示或脚本访问时丢失
    原始信息。
    """
    return x.decode("utf-8", "surrogateescape")


def _always_bytes(x: str | bytes) -> bytes:
    """
    将字符串或字节统一转换为 HTTP 头内部使用的字节形式。

    与 `_native` 配套使用 UTF-8 和 `surrogateescape`，保证字符串和原始
    字节之间可以尽量无损往返。
    """
    return strutils.always_bytes(x, "utf-8", "surrogateescape")


# This cannot be easily typed with mypy yet, so we just specify MultiDict without concrete types.
class Headers(multidict.MultiDict):  # type: ignore
    """
    Header class which allows both convenient access to individual headers as well as
    direct access to the underlying raw data. Provides a full dictionary interface.

    Create headers with keyword arguments:
    >>> h = Headers(host="example.com", content_type="application/xml")

    Headers mostly behave like a normal dict:
    >>> h["Host"]
    "example.com"

    Headers are case insensitive:
    >>> h["host"]
    "example.com"

    Headers can also be created from a list of raw (header_name, header_value) byte tuples:
    >>> h = Headers([
        (b"Host",b"example.com"),
        (b"Accept",b"text/html"),
        (b"accept",b"application/xml")
    ])

    Multiple headers are folded into a single header as per RFC 7230:
    >>> h["Accept"]
    "text/html, application/xml"

    Setting a header removes all existing headers with the same name:
    >>> h["Accept"] = "application/text"
    >>> h["Accept"]
    "application/text"

    `bytes(h)` returns an HTTP/1 header block:
    >>> print(bytes(h))
    Host: example.com
    Accept: application/text

    For full control, the raw header fields can be accessed:
    >>> h.fields

    Caveats:
     - For use with the "Set-Cookie" and "Cookie" headers, either use `Response.cookies` or see `Headers.get_all`.
    """

    def __init__(self, fields: Iterable[tuple[bytes, bytes]] = (), **headers):
        """
        *Args:*
         - *fields:* (optional) list of ``(name, value)`` header byte tuples,
           e.g. ``[(b"Host", b"example.com")]``. All names and values must be bytes.
         - *\\*\\*headers:* Additional headers to set. Will overwrite existing values from `fields`.
           For convenience, underscores in header names will be transformed to dashes -
           this behaviour does not extend to other methods.

        If ``**headers`` contains multiple keys that have equal ``.lower()`` representations,
        the behavior is undefined.
        """
        super().__init__(fields)

        for key, value in self.fields:
            if not isinstance(key, bytes) or not isinstance(value, bytes):
                raise TypeError("Header fields must be bytes.")

        # content_type -> content-type
        self.update(
            {
                _always_bytes(name).replace(b"_", b"-"): _always_bytes(value)
                for name, value in headers.items()
            }
        )

    fields: tuple[tuple[bytes, bytes], ...]

    @staticmethod
    def _reduce_values(values) -> str:
        """
        将同名 HTTP 头的多个值折叠为单个展示值。

        普通 HTTP 头按 RFC 语义可以用逗号合并；不能合并的头（例如
        Set-Cookie）应通过 `get_all()` 读取。
        """
        # Headers can be folded
        return ", ".join(values)

    @staticmethod
    def _kconv(key) -> str:
        """
        归一化 HTTP 头名用于大小写不敏感查找。
        """
        # Headers are case-insensitive
        return key.lower()

    def __bytes__(self) -> bytes:
        """
        将头字段序列化为 HTTP/1 使用的 CRLF 分隔字节块。
        """
        if self.fields:
            return b"\r\n".join(b": ".join(field) for field in self.fields) + b"\r\n"
        else:
            return b""

    def __delitem__(self, key: str | bytes) -> None:
        """
        删除指定头字段，支持字符串或字节形式的头名。
        """
        key = _always_bytes(key)
        super().__delitem__(key)

    def __iter__(self) -> Iterator[str]:
        """
        以字符串形式迭代头名。
        """
        for x in super().__iter__():
            yield _native(x)

    def get_all(self, name: str | bytes) -> list[str]:
        """
        Like `Headers.get`, but does not fold multiple headers into a single one.
        This is useful for Set-Cookie and Cookie headers, which do not support folding.

        *See also:*
         - <https://tools.ietf.org/html/rfc7230#section-3.2.2>
         - <https://datatracker.ietf.org/doc/html/rfc6265#section-5.4>
         - <https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.5>
        """
        name = _always_bytes(name)
        return [_native(x) for x in super().get_all(name)]

    def set_all(self, name: str | bytes, values: Iterable[str | bytes]):
        """
        Explicitly set multiple headers for the given key.
        See `Headers.get_all`.
        """
        name = _always_bytes(name)
        values = [_always_bytes(x) for x in values]
        return super().set_all(name, values)

    def insert(self, index: int, key: str | bytes, value: str | bytes):
        """
        在指定位置插入一个原始头字段，同时完成字符串到字节的转换。
        """
        key = _always_bytes(key)
        value = _always_bytes(value)
        super().insert(index, key, value)

    def items(self, multi=False):
        """
        返回头字段键值对。

        `multi=False` 时同名头按 `MultiDict` 规则折叠；`multi=True` 时保留
        所有原始字段顺序和重复项，适合 Set-Cookie 等不能折叠的头。
        """
        if multi:
            return ((_native(k), _native(v)) for k, v in self.fields)
        else:
            return super().items()


@dataclass
class MessageData(serializable.Serializable):
    """
    Request 和 Response 共享的底层可序列化数据容器。

    这个类只保存协议字段，不提供高级访问逻辑；高级属性和编码/解码逻辑在
    `Message` 上实现。
    """

    http_version: bytes
    headers: Headers
    content: bytes | None
    trailers: Headers | None
    timestamp_start: float
    timestamp_end: float | None

    # noinspection PyUnreachableCode
    if __debug__:

        def __post_init__(self):
            """
            在调试模式下校验 dataclass 字段类型。
            """
            for field in fields(self):
                val = getattr(self, field.name)
                typecheck.check_option_type(field.name, val, field.type)

    def set_state(self, state):
        """
        从序列化状态恢复消息数据。

        headers 和 trailers 在状态中是普通可序列化结构，恢复时需要转回
        `Headers` 实例。
        """
        for k, v in state.items():
            if k in ("headers", "trailers") and v is not None:
                v = Headers.from_state(v)
            setattr(self, k, v)

    def get_state(self):
        """
        导出可持久化的消息状态。

        Headers 本身也有状态格式，所以这里递归调用其 `get_state()`。
        """
        state = vars(self).copy()
        state["headers"] = state["headers"].get_state()
        if state["trailers"] is not None:
            state["trailers"] = state["trailers"].get_state()
        return state

    @classmethod
    def from_state(cls, state):
        """
        根据序列化状态创建消息数据对象。
        """
        state["headers"] = Headers.from_state(state["headers"])
        if state["trailers"] is not None:
            state["trailers"] = Headers.from_state(state["trailers"])
        return cls(**state)


@dataclass
class RequestData(MessageData):
    """
    HTTP 请求专有的底层数据。

    host/port 是 mitmproxy 归一化后的目标地址；method、scheme、authority、
    path 保留为字节，方便忠实表达不同 HTTP 版本中的请求行或伪头字段。
    """

    host: str
    port: int
    method: bytes
    scheme: bytes
    authority: bytes
    path: bytes


@dataclass
class ResponseData(MessageData):
    """
    HTTP 响应专有的底层数据。
    """

    status_code: int
    reason: bytes


class Message(serializable.Serializable):
    """Base class for `Request` and `Response`."""

    @classmethod
    def from_state(cls, state):
        """
        从序列化状态创建 Request 或 Response。
        """
        return cls(**state)

    def get_state(self):
        """
        返回底层 `MessageData` 的可序列化状态。
        """
        return self.data.get_state()

    def set_state(self, state):
        """
        用给定状态更新底层 `MessageData`。
        """
        self.data.set_state(state)

    data: MessageData
    stream: Callable[[bytes], Iterable[bytes] | bytes] | bool = False
    """
    This attribute controls if the message body should be streamed.

    If `False`, mitmproxy will buffer the entire body before forwarding it to the destination.
    This makes it possible to perform string replacements on the entire body.
    If `True`, the message body will not be buffered on the proxy
    but immediately forwarded instead.
    Alternatively, a transformation function can be specified, which will be called for each chunk of data.
    Please note that packet boundaries generally should not be relied upon.

    This attribute must be set in the `requestheaders` or `responseheaders` hook.
    Setting it in `request` or  `response` is already too late, mitmproxy has buffered the message body already.
    """

    @property
    def http_version(self) -> str:
        """
        HTTP version string, for example `HTTP/1.1`.
        """
        return self.data.http_version.decode("utf-8", "surrogateescape")

    @http_version.setter
    def http_version(self, http_version: str | bytes) -> None:
        """
        设置 HTTP 版本字符串，内部统一保存为字节。
        """
        self.data.http_version = strutils.always_bytes(
            http_version, "utf-8", "surrogateescape"
        )

    @property
    def is_http10(self) -> bool:
        """
        当前消息是否属于 HTTP/1.0。
        """
        return self.data.http_version == b"HTTP/1.0"

    @property
    def is_http11(self) -> bool:
        """
        当前消息是否属于 HTTP/1.1。
        """
        return self.data.http_version == b"HTTP/1.1"

    @property
    def is_http2(self) -> bool:
        """
        当前消息是否属于 HTTP/2。
        """
        return self.data.http_version == b"HTTP/2.0"

    @property
    def is_http3(self) -> bool:
        """
        当前消息是否属于 HTTP/3。
        """
        return self.data.http_version == b"HTTP/3"

    @property
    def headers(self) -> Headers:
        """
        The HTTP headers.
        """
        return self.data.headers

    @headers.setter
    def headers(self, h: Headers) -> None:
        """
        替换消息头对象。
        """
        self.data.headers = h

    @property
    def trailers(self) -> Headers | None:
        """
        The [HTTP trailers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer).
        """
        return self.data.trailers

    @trailers.setter
    def trailers(self, h: Headers | None) -> None:
        """
        替换 HTTP trailers。
        """
        self.data.trailers = h

    @property
    def raw_content(self) -> bytes | None:
        """
        The raw (potentially compressed) HTTP message body.

        In contrast to `Message.content` and `Message.text`, accessing this property never raises.
        `raw_content` may be `None` if the content is missing, for example due to body streaming
        (see `Message.stream`). In contrast, `b""` signals a present but empty message body.

        *See also:* `Message.content`, `Message.text`
        """
        return self.data.content

    @raw_content.setter
    def raw_content(self, content: bytes | None) -> None:
        """
        设置原始消息体，不进行 Content-Encoding 编码或解码。
        """
        self.data.content = content

    @property
    def content(self) -> bytes | None:
        """
        The uncompressed HTTP message body as bytes.

        Accessing this attribute may raise a `ValueError` when the HTTP content-encoding is invalid.

        *See also:* `Message.raw_content`, `Message.text`
        """
        return self.get_content()

    @content.setter
    def content(self, value: bytes | None) -> None:
        """
        设置未压缩消息体，并根据当前 Content-Encoding 重新编码保存。
        """
        self.set_content(value)

    @property
    def text(self) -> str | None:
        """
        The uncompressed and decoded HTTP message body as text.

        Accessing this attribute may raise a `ValueError` when either content-encoding or charset is invalid.

        *See also:* `Message.raw_content`, `Message.content`
        """
        return self.get_text()

    @text.setter
    def text(self, value: str | None) -> None:
        """
        设置文本消息体，并根据 Content-Type 中的 charset 编码为字节。
        """
        self.set_text(value)

    def set_content(self, value: bytes | None) -> None:
        """
        设置未压缩的字节消息体。

        算法上先查看当前 `Content-Encoding`，尝试把传入的明文字节重新编码
        为 wire format 后保存到 `raw_content`。如果现有编码非法，则删除
        该头并退回到 identity。最后在没有 Transfer-Encoding 时同步更新
        Content-Length。
        """
        if value is None:
            self.raw_content = None
            return
        if not isinstance(value, bytes):
            raise TypeError(
                f"Message content must be bytes, not {type(value).__name__}. "
                "Please use .text if you want to assign a str."
            )
        ce = self.headers.get("content-encoding")
        try:
            self.raw_content = encoding.encode(value, ce or "identity")
        except ValueError:
            # So we have an invalid content-encoding?
            # Let's remove it!
            del self.headers["content-encoding"]
            self.raw_content = value

        if "transfer-encoding" in self.headers:
            # https://httpwg.org/specs/rfc7230.html#header.content-length
            # don't set content-length if a transfer-encoding is provided
            pass
        else:
            self.headers["content-length"] = str(len(self.raw_content))

    def get_content(self, strict: bool = True) -> bytes | None:
        """
        Similar to `Message.content`, but does not raise if `strict` is `False`.
        Instead, the compressed message body is returned as-is.
        """
        if self.raw_content is None:
            return None
        ce = self.headers.get("content-encoding")
        if ce:
            try:
                content = encoding.decode(self.raw_content, ce)
                # A client may illegally specify a byte -> str encoding here (e.g. utf8)
                if isinstance(content, str):
                    raise ValueError(f"Invalid Content-Encoding: {ce}")
                return content
            except ValueError:
                if strict:
                    raise
                return self.raw_content
        else:
            return self.raw_content

    def set_text(self, text: str | None) -> None:
        """
        设置文本消息体。

        先根据 Content-Type 推断字符集，再编码为字节并走 `content` setter。
        如果 Content-Type 中声明的字符集不可用，则回退为 UTF-8，并同步改写
        Content-Type 的 charset。
        """
        if text is None:
            self.content = None
            return
        enc = infer_content_encoding(self.headers.get("content-type", ""))

        try:
            self.content = cast(bytes, encoding.encode(text, enc))
        except ValueError:
            # Fall back to UTF-8 and update the content-type header.
            ct = parse_content_type(self.headers.get("content-type", "")) or (
                "text",
                "plain",
                {},
            )
            ct[2]["charset"] = "utf-8"
            self.headers["content-type"] = assemble_content_type(*ct)
            enc = "utf8"
            self.content = text.encode(enc, "surrogateescape")

    def get_text(self, strict: bool = True) -> str | None:
        """
        Similar to `Message.text`, but does not raise if `strict` is `False`.
        Instead, the message body is returned as surrogate-escaped UTF-8.
        """
        content = self.get_content(strict)
        if content is None:
            return None
        enc = infer_content_encoding(self.headers.get("content-type", ""), content)
        try:
            return cast(str, encoding.decode(content, enc))
        except ValueError:
            if strict:
                raise
            return content.decode("utf8", "surrogateescape")

    @property
    def timestamp_start(self) -> float:
        """
        *Timestamp:* Headers received.
        """
        return self.data.timestamp_start

    @timestamp_start.setter
    def timestamp_start(self, timestamp_start: float) -> None:
        """
        设置消息头接收时间戳。
        """
        self.data.timestamp_start = timestamp_start

    @property
    def timestamp_end(self) -> float | None:
        """
        *Timestamp:* Last byte received.
        """
        return self.data.timestamp_end

    @timestamp_end.setter
    def timestamp_end(self, timestamp_end: float | None):
        """
        设置消息最后一个字节接收时间戳。
        """
        self.data.timestamp_end = timestamp_end

    def decode(self, strict: bool = True) -> None:
        """
        Decodes body based on the current Content-Encoding header, then
        removes the header.

        If the message body is missing or empty, no action is taken.

        *Raises:*
         - `ValueError`, when the content-encoding is invalid and strict is True.
        """
        if not self.raw_content:
            # The body is missing (for example, because of body streaming or because it's a response
            # to a HEAD request), so we can't correctly update content-length.
            return
        decoded = self.get_content(strict)
        self.headers.pop("content-encoding", None)
        self.content = decoded

    def encode(self, encoding: str) -> None:
        """
        Encodes body with the given encoding, where e is "gzip", "deflate", "identity", "br", or "zstd".
        Any existing content-encodings are overwritten, the content is not decoded beforehand.

        *Raises:*
         - `ValueError`, when the specified content-encoding is invalid.
        """
        self.headers["content-encoding"] = encoding
        self.content = self.raw_content
        if "content-encoding" not in self.headers:
            raise ValueError(f"Invalid content encoding {encoding!r}")

    def json(self, **kwargs: Any) -> Any:
        """
        Returns the JSON encoded content of the response, if any.
        `**kwargs` are optional arguments that will be
        passed to `json.loads()`.

        Will raise if the content can not be decoded and then parsed as JSON.

        *Raises:*
         - `json.decoder.JSONDecodeError` if content is not valid JSON.
         - `TypeError` if the content is not available, for example because the response
            has been streamed.
        """
        content = self.get_content(strict=False)
        if content is None:
            raise TypeError("Message content is not available.")
        else:
            return json.loads(content, **kwargs)


class Request(Message):
    """
    An HTTP request.
    """

    data: RequestData

    def __init__(
        self,
        host: str,
        port: int,
        method: bytes,
        scheme: bytes,
        authority: bytes,
        path: bytes,
        http_version: bytes,
        headers: Headers | tuple[tuple[bytes, bytes], ...],
        content: bytes | None,
        trailers: Headers | tuple[tuple[bytes, bytes], ...] | None,
        timestamp_start: float,
        timestamp_end: float | None,
    ):
        """
        创建 HTTP 请求对象。

        构造函数接受协议层解析出的原始字段，并为了兼容旧代码自动转换部分
        历史上可能传入的字符串/字节类型。headers 和 trailers 会统一包装为
        `Headers`，后续属性访问都基于 `RequestData`。
        """
        # auto-convert invalid types to retain compatibility with older code.
        if isinstance(host, bytes):
            host = host.decode("idna", "strict")
        if isinstance(method, str):
            method = method.encode("ascii", "strict")
        if isinstance(scheme, str):
            scheme = scheme.encode("ascii", "strict")
        if isinstance(authority, str):
            authority = authority.encode("ascii", "strict")
        if isinstance(path, str):
            path = path.encode("ascii", "strict")
        if isinstance(http_version, str):
            http_version = http_version.encode("ascii", "strict")

        if isinstance(content, str):
            raise ValueError(f"Content must be bytes, not {type(content).__name__}")
        if not isinstance(headers, Headers):
            headers = Headers(headers)
        if trailers is not None and not isinstance(trailers, Headers):
            trailers = Headers(trailers)

        self.data = RequestData(
            host=host,
            port=port,
            method=method,
            scheme=scheme,
            authority=authority,
            path=path,
            http_version=http_version,
            headers=headers,
            content=content,
            trailers=trailers,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )

    def __repr__(self) -> str:
        """
        返回适合调试日志使用的简短请求描述。
        """
        if self.host and self.port:
            hostport = f"{self.host}:{self.port}"
        else:
            hostport = ""
        path = self.path or ""
        return f"Request({self.method} {hostport}{path})"

    @classmethod
    def make(
        cls,
        method: str,
        url: str,
        content: bytes | str = "",
        headers: (
            Headers | dict[str | bytes, str | bytes] | Iterable[tuple[bytes, bytes]]
        ) = (),
    ) -> "Request":
        """
        Simplified API for creating request objects.
        """
        # Headers can be list or dict, we differentiate here.
        if isinstance(headers, Headers):
            pass
        elif isinstance(headers, dict):
            headers = Headers(
                (
                    always_bytes(k, "utf-8", "surrogateescape"),
                    always_bytes(v, "utf-8", "surrogateescape"),
                )
                for k, v in headers.items()
            )
        elif isinstance(headers, Iterable):
            headers = Headers(headers)  # type: ignore
        else:
            raise TypeError(
                "Expected headers to be an iterable or dict, but is {}.".format(
                    type(headers).__name__
                )
            )

        req = cls(
            "",
            0,
            method.encode("utf-8", "surrogateescape"),
            b"",
            b"",
            b"",
            b"HTTP/1.1",
            headers,
            b"",
            None,
            time.time(),
            time.time(),
        )

        req.url = url
        # Assign this manually to update the content-length header.
        if isinstance(content, bytes):
            req.content = content
        elif isinstance(content, str):
            req.text = content
        else:
            raise TypeError(
                f"Expected content to be str or bytes, but is {type(content).__name__}."
            )

        return req

    @property
    def first_line_format(self) -> str:
        """
        *Read-only:* HTTP request form as defined in [RFC 7230](https://tools.ietf.org/html/rfc7230#section-5.3).

        origin-form and asterisk-form are subsumed as "relative".
        """
        if self.method == "CONNECT":
            return "authority"
        elif self.authority:
            return "absolute"
        else:
            return "relative"

    @property
    def method(self) -> str:
        """
        HTTP request method, e.g. "GET".
        """
        return self.data.method.decode("utf-8", "surrogateescape").upper()

    @method.setter
    def method(self, val: str | bytes) -> None:
        """
        设置 HTTP 方法，内部统一保存为字节。
        """
        self.data.method = always_bytes(val, "utf-8", "surrogateescape")

    @property
    def scheme(self) -> str:
        """
        HTTP request scheme, which should be "http" or "https".
        """
        return self.data.scheme.decode("utf-8", "surrogateescape")

    @scheme.setter
    def scheme(self, val: str | bytes) -> None:
        """
        设置请求 scheme，例如 http 或 https。
        """
        self.data.scheme = always_bytes(val, "utf-8", "surrogateescape")

    @property
    def authority(self) -> str:
        """
        HTTP request authority.

        For HTTP/1, this is the authority portion of the request target
        (in either absolute-form or authority-form).
        For origin-form and asterisk-form requests, this property is set to an empty string.

        For HTTP/2, this is the :authority pseudo header.

        *See also:* `Request.host`, `Request.host_header`, `Request.pretty_host`
        """
        try:
            return self.data.authority.decode("idna")
        except UnicodeError:
            return self.data.authority.decode("utf8", "surrogateescape")

    @authority.setter
    def authority(self, val: str | bytes) -> None:
        """
        设置请求 authority。

        域名优先按 IDNA 编码保存；如果不是合法 IDNA，则使用 UTF-8 与
        `surrogateescape` 尽量保留原始值。
        """
        if isinstance(val, str):
            try:
                val = val.encode("idna", "strict")
            except UnicodeError:
                val = val.encode("utf8", "surrogateescape")  # type: ignore
        self.data.authority = val

    @property
    def host(self) -> str:
        """
        Target server for this request. This may be parsed from the raw request
        (e.g. from a ``GET http://example.com/ HTTP/1.1`` request line)
        or inferred from the proxy mode (e.g. an IP in transparent mode).

        Setting the host attribute also updates the host header and authority information, if present.

        *See also:* `Request.authority`, `Request.host_header`, `Request.pretty_host`
        """
        return self.data.host

    @host.setter
    def host(self, val: str | bytes) -> None:
        """
        设置目标主机，并同步已有 Host 头和 authority。
        """
        self.data.host = always_str(val, "idna", "strict")
        self._update_host_and_authority()

    @property
    def host_header(self) -> str | None:
        """
        The request's host/authority header.

        This property maps to either ``request.headers["Host"]`` or
        ``request.authority``, depending on whether it's HTTP/1.x or HTTP/2.0.

        *See also:* `Request.authority`,`Request.host`, `Request.pretty_host`
        """
        if self.is_http2 or self.is_http3:
            return self.authority or self.data.headers.get("Host", None)
        else:
            return self.data.headers.get("Host", None)

    @host_header.setter
    def host_header(self, val: None | str | bytes) -> None:
        """
        设置请求中的 Host/authority 头。

        HTTP/2 和 HTTP/3 以 `:authority` 为主；HTTP/1 使用 Host 头。这里按
        版本差异更新对应字段，避免在 h2/h3 中错误创建多余 Host 头。
        """
        if val is None:
            if self.is_http2 or self.is_http3:
                self.data.authority = b""
            self.headers.pop("Host", None)
        else:
            if self.is_http2 or self.is_http3:
                self.authority = val  # type: ignore
            if not (self.is_http2 or self.is_http3) or "Host" in self.headers:
                # For h2, we only overwrite, but not create, as :authority is the h2 host header.
                self.headers["Host"] = val

    @property
    def port(self) -> int:
        """
        Target port.
        """
        return self.data.port

    @port.setter
    def port(self, port: int) -> None:
        """
        设置目标端口，并同步已有 Host 头和 authority。
        """
        if not isinstance(port, int):
            raise ValueError(f"Port must be an integer, not {port!r}.")

        self.data.port = port
        self._update_host_and_authority()

    def _update_host_and_authority(self) -> None:
        """
        在 host 或 port 变化后同步 Host 头和 authority。

        算法只更新已经存在的字段：如果请求原本没有 Host 头或 authority，就
        不主动创建。这样可以尽量保留原始请求形态，同时保证已有目标字段不
        与 `host`/`port` 脱节。
        """
        val = url.hostport(self.scheme, self.host, self.port)

        # Update host header
        if "Host" in self.data.headers:
            self.data.headers["Host"] = val
        # Update authority
        if self.data.authority:
            self.authority = val

    @property
    def path(self) -> str:
        """
        HTTP request path, e.g. "/index.html" or "/index.html?a=b".
        Usually starts with a slash, except for OPTIONS requests, which may just be "*".

        This attribute includes both path and query parts of the target URI
        (see Sections 3.3 and 3.4 of [RFC3986](https://datatracker.ietf.org/doc/html/rfc3986)).
        """
        return self.data.path.decode("utf-8", "surrogateescape")

    @path.setter
    def path(self, val: str | bytes) -> None:
        """
        设置请求 path，内部保存为 UTF-8 字节。
        """
        self.data.path = always_bytes(val, "utf-8", "surrogateescape")

    @property
    def url(self) -> str:
        """
        The full URL string, constructed from `Request.scheme`, `Request.host`, `Request.port` and `Request.path`.

        Settings this property updates these attributes as well.
        """
        if self.first_line_format == "authority":
            return f"{self.host}:{self.port}"
        path = self.path if self.path != "*" else ""
        return url.unparse(self.scheme, self.host, self.port, path)

    @url.setter
    def url(self, val: str | bytes) -> None:
        """
        设置完整 URL，并拆分更新 scheme、host、port 和 path。
        """
        val = always_str(val, "utf-8", "surrogateescape")
        self.scheme, self.host, self.port, self.path = url.parse(val)  # type: ignore

    @property
    def pretty_host(self) -> str:
        """
        *Read-only:* Like `Request.host`, but using `Request.host_header` header as an additional (preferred) data source.
        This is useful in transparent mode where `Request.host` is only an IP address.

        *Warning:* When working in adversarial environments, this may not reflect the actual destination
        as the Host header could be spoofed.
        """
        authority = self.host_header
        if authority:
            return url.parse_authority(authority, check=False)[0]
        else:
            return self.host

    @property
    def pretty_url(self) -> str:
        """
        *Read-only:* Like `Request.url`, but using `Request.pretty_host` instead of `Request.host`.
        """
        if self.first_line_format == "authority":
            return self.authority

        host_header = self.host_header
        if not host_header:
            return self.url

        pretty_host, pretty_port = url.parse_authority(host_header, check=False)
        pretty_port = pretty_port or url.default_port(self.scheme) or 443
        path = self.path if self.path != "*" else ""

        return url.unparse(self.scheme, pretty_host, pretty_port, path)

    def _get_query(self):
        """
        从当前 URL 中解析查询参数，返回 MultiDictView 使用的元组数据。
        """
        query = urllib.parse.urlparse(self.url).query
        return tuple(url.decode(query))

    def _set_query(self, query_data):
        """
        将查询参数写回请求 path。

        只替换 query 部分，保留 path、params 和 fragment。
        """
        query = url.encode(query_data)
        _, _, path, params, _, fragment = urllib.parse.urlparse(self.url)
        self.path = urllib.parse.urlunparse(["", "", path, params, query, fragment])

    @property
    def query(self) -> multidict.MultiDictView[str, str]:
        """
        The request query as a mutable mapping view on the request's path.
        For the most part, this behaves like a dictionary.
        Modifications to the MultiDictView update `Request.path`, and vice versa.
        """
        return multidict.MultiDictView(self._get_query, self._set_query)

    @query.setter
    def query(self, value):
        """
        替换整个查询参数集合。
        """
        self._set_query(value)

    def _get_cookies(self):
        """
        从一个或多个 Cookie 头中解析请求 cookie。
        """
        h = self.headers.get_all("Cookie")
        return tuple(cookies.parse_cookie_headers(h))

    def _set_cookies(self, value):
        """
        将 cookie 集合格式化回 Cookie 头。
        """
        self.headers["cookie"] = cookies.format_cookie_header(value)

    @property
    def cookies(self) -> multidict.MultiDictView[str, str]:
        """
        The request cookies.
        For the most part, this behaves like a dictionary.
        Modifications to the MultiDictView update `Request.headers`, and vice versa.
        """
        return multidict.MultiDictView(self._get_cookies, self._set_cookies)

    @cookies.setter
    def cookies(self, value):
        """
        替换请求 cookie 集合。
        """
        self._set_cookies(value)

    @property
    def path_components(self) -> tuple[str, ...]:
        """
        The URL's path components as a tuple of strings.
        Components are unquoted.
        """
        path = urllib.parse.urlparse(self.url).path
        # This needs to be a tuple so that it's immutable.
        # Otherwise, this would fail silently:
        #   request.path_components.append("foo")
        return tuple(url.unquote(i) for i in path.split("/") if i)

    @path_components.setter
    def path_components(self, components: Iterable[str]):
        """
        替换 URL path 的各级路径组件。

        每个组件都会单独 URL-quote，再重新拼接为 path，同时保留原有 params、
        query 和 fragment。
        """
        components = map(lambda x: url.quote(x, safe=""), components)
        path = "/" + "/".join(components)
        _, _, _, params, query, fragment = urllib.parse.urlparse(self.url)
        self.path = urllib.parse.urlunparse(["", "", path, params, query, fragment])

    def anticache(self) -> None:
        """
        Modifies this request to remove headers that might produce a cached response.
        """
        delheaders = (
            "if-modified-since",
            "if-none-match",
        )
        for i in delheaders:
            self.headers.pop(i, None)

    def anticomp(self) -> None:
        """
        Modify the Accept-Encoding header to only accept uncompressed responses.
        """
        self.headers["accept-encoding"] = "identity"

    def constrain_encoding(self) -> None:
        """
        Limits the permissible Accept-Encoding values, based on what we can decode appropriately.
        """
        accept_encoding = self.headers.get("accept-encoding")
        if accept_encoding:
            self.headers["accept-encoding"] = ", ".join(
                e
                for e in {"gzip", "identity", "deflate", "br", "zstd"}
                if e in accept_encoding
            )

    def _get_urlencoded_form(self):
        """
        尝试从请求体中解析 application/x-www-form-urlencoded 表单。

        只有 Content-Type 匹配时才解析；解析失败或类型不匹配时返回空集合，
        让 `urlencoded_form` 呈现为空的可变视图。
        """
        is_valid_content_type = (
            "application/x-www-form-urlencoded"
            in self.headers.get("content-type", "").lower()
        )
        if is_valid_content_type:
            return tuple(url.decode(self.get_text(strict=False)))
        return ()

    def _set_urlencoded_form(self, form_data: Sequence[tuple[str, str]]) -> None:
        """
        Sets the body to the URL-encoded form data, and adds the appropriate content-type header.
        This will overwrite the existing content if there is one.
        """
        self.headers["content-type"] = "application/x-www-form-urlencoded"
        self.content = url.encode(form_data, self.get_text(strict=False)).encode()

    @property
    def urlencoded_form(self) -> multidict.MultiDictView[str, str]:
        """
        The URL-encoded form data.

        If the content-type indicates non-form data or the form could not be parsed, this is set to
        an empty `MultiDictView`.

        Modifications to the MultiDictView update `Request.content`, and vice versa.
        """
        return multidict.MultiDictView(
            self._get_urlencoded_form, self._set_urlencoded_form
        )

    @urlencoded_form.setter
    def urlencoded_form(self, value):
        """
        替换 URL-encoded 表单数据。
        """
        self._set_urlencoded_form(value)

    def _get_multipart_form(self) -> list[tuple[bytes, bytes]]:
        """
        尝试从请求体中解析 multipart/form-data 表单。

        multipart 解析依赖 Content-Type 中的 boundary；如果类型不匹配、
        body 缺失或解析失败，则返回空列表。
        """
        is_valid_content_type = (
            "multipart/form-data" in self.headers.get("content-type", "").lower()
        )
        if is_valid_content_type and self.content is not None:
            try:
                return multipart.decode_multipart(
                    self.headers.get("content-type"), self.content
                )
            except ValueError:
                pass
        return []

    def _set_multipart_form(self, value: list[tuple[bytes, bytes]]) -> None:
        """
        将 multipart 表单字段写回请求体。

        如果当前 Content-Type 不是 multipart/form-data，则生成一个随机
        boundary 并写入 Content-Type。随后使用该 boundary 重新编码整个
        multipart body。
        """
        ct = self.headers.get("content-type", "")
        is_valid_content_type = ct.lower().startswith("multipart/form-data")
        if not is_valid_content_type:
            """
            Generate a random boundary here.

            See <https://datatracker.ietf.org/doc/html/rfc2046#section-5.1.1> for specifications
            on generating the boundary.
            """
            boundary = "-" * 20 + binascii.hexlify(os.urandom(16)).decode()
            self.headers["content-type"] = ct = f"multipart/form-data; {boundary=!s}"
        self.content = multipart.encode_multipart(ct, value)

    @property
    def multipart_form(self) -> multidict.MultiDictView[bytes, bytes]:
        """
        The multipart form data.

        If the content-type indicates non-form data or the form could not be parsed, this is set to
        an empty `MultiDictView`.

        Modifications to the MultiDictView update `Request.content`, and vice versa.
        """
        return multidict.MultiDictView(
            self._get_multipart_form, self._set_multipart_form
        )

    @multipart_form.setter
    def multipart_form(self, value: list[tuple[bytes, bytes]]) -> None:
        """
        替换 multipart 表单数据。
        """
        self._set_multipart_form(value)


class Response(Message):
    """
    An HTTP response.
    """

    data: ResponseData

    def __init__(
        self,
        http_version: bytes,
        status_code: int,
        reason: bytes,
        headers: Headers | tuple[tuple[bytes, bytes], ...],
        content: bytes | None,
        trailers: None | Headers | tuple[tuple[bytes, bytes], ...],
        timestamp_start: float,
        timestamp_end: float | None,
    ):
        """
        创建 HTTP 响应对象。

        与 `Request.__init__` 类似，这里接收协议层解析出的原始字段，并为了
        兼容旧代码转换部分历史类型。headers 和 trailers 会被统一包装为
        `Headers`。
        """
        # auto-convert invalid types to retain compatibility with older code.
        if isinstance(http_version, str):
            http_version = http_version.encode("ascii", "strict")
        if isinstance(reason, str):
            reason = reason.encode("ascii", "strict")

        if isinstance(content, str):
            raise ValueError(f"Content must be bytes, not {type(content).__name__}")
        if not isinstance(headers, Headers):
            headers = Headers(headers)
        if trailers is not None and not isinstance(trailers, Headers):
            trailers = Headers(trailers)

        self.data = ResponseData(
            http_version=http_version,
            status_code=status_code,
            reason=reason,
            headers=headers,
            content=content,
            trailers=trailers,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )

    def __repr__(self) -> str:
        """
        返回适合调试日志使用的简短响应描述。
        """
        if self.raw_content:
            ct = self.headers.get("content-type", "unknown content type")
            size = human.pretty_size(len(self.raw_content))
            details = f"{ct}, {size}"
        else:
            details = "no content"
        return f"Response({self.status_code}, {details})"

    @classmethod
    def make(
        cls,
        status_code: int = 200,
        content: bytes | str = b"",
        headers: (
            Headers | Mapping[str, str | bytes] | Iterable[tuple[bytes, bytes]]
        ) = (),
    ) -> "Response":
        """
        Simplified API for creating response objects.
        """
        if isinstance(headers, Headers):
            headers = headers
        elif isinstance(headers, dict):
            headers = Headers(
                (
                    always_bytes(k, "utf-8", "surrogateescape"),  # type: ignore
                    always_bytes(v, "utf-8", "surrogateescape"),
                )
                for k, v in headers.items()
            )
        elif isinstance(headers, Iterable):
            headers = Headers(headers)  # type: ignore
        else:
            raise TypeError(
                "Expected headers to be an iterable or dict, but is {}.".format(
                    type(headers).__name__
                )
            )

        resp = cls(
            b"HTTP/1.1",
            status_code,
            status_codes.RESPONSES.get(status_code, "").encode(),
            headers,
            None,
            None,
            time.time(),
            time.time(),
        )

        # Assign this manually to update the content-length header.
        if isinstance(content, bytes):
            resp.content = content
        elif isinstance(content, str):
            resp.text = content
        else:
            raise TypeError(
                f"Expected content to be str or bytes, but is {type(content).__name__}."
            )

        return resp

    @property
    def status_code(self) -> int:
        """
        HTTP Status Code, e.g. ``200``.
        """
        return self.data.status_code

    @status_code.setter
    def status_code(self, status_code: int) -> None:
        """
        设置 HTTP 状态码。
        """
        self.data.status_code = status_code

    @property
    def reason(self) -> str:
        """
        HTTP reason phrase, for example "Not Found".

        HTTP/2 responses do not contain a reason phrase, an empty string will be returned instead.
        """
        # Encoding: http://stackoverflow.com/a/16674906/934719
        return self.data.reason.decode("ISO-8859-1")

    @reason.setter
    def reason(self, reason: str | bytes) -> None:
        """
        设置 HTTP reason phrase，内部按 ISO-8859-1 保存。
        """
        self.data.reason = strutils.always_bytes(reason, "ISO-8859-1")

    def _get_cookies(self):
        """
        从所有 Set-Cookie 头中解析响应 cookie。
        """
        h = self.headers.get_all("set-cookie")
        all_cookies = cookies.parse_set_cookie_headers(h)
        return tuple((name, (value, attrs)) for name, value, attrs in all_cookies)

    def _set_cookies(self, value):
        """
        将响应 cookie 集合格式化回多个 Set-Cookie 头。
        """
        cookie_headers = []
        for k, v in value:
            header = cookies.format_set_cookie_header([(k, v[0], v[1])])
            cookie_headers.append(header)
        self.headers.set_all("set-cookie", cookie_headers)

    @property
    def cookies(
        self,
    ) -> multidict.MultiDictView[str, tuple[str, multidict.MultiDict[str, str | None]]]:
        """
        The response cookies. A possibly empty `MultiDictView`, where the keys are cookie
        name strings, and values are `(cookie value, attributes)` tuples. Within
        attributes, unary attributes (e.g. `HTTPOnly`) are indicated by a `None` value.
        Modifications to the MultiDictView update `Response.headers`, and vice versa.

        *Warning:* Changes to `attributes` will not be picked up unless you also reassign
        the `(cookie value, attributes)` tuple directly in the `MultiDictView`.
        """
        return multidict.MultiDictView(self._get_cookies, self._set_cookies)

    @cookies.setter
    def cookies(self, value):
        """
        替换响应 cookie 集合。
        """
        self._set_cookies(value)

    def refresh(self, now=None):
        """
        This fairly complex and heuristic function refreshes a server
        response for replay.

         - It adjusts date, expires, and last-modified headers.
         - It adjusts cookie expiration.
        """
        if not now:
            now = time.time()
        delta = now - self.timestamp_start
        refresh_headers = [
            "date",
            "expires",
            "last-modified",
        ]
        for i in refresh_headers:
            if i in self.headers:
                d = parsedate_tz(self.headers[i])
                if d:
                    new = mktime_tz(d) + delta
                    try:
                        self.headers[i] = formatdate(new, usegmt=True)
                    except OSError:  # pragma: no cover
                        pass  # value out of bounds on Windows only (which is why we exclude it from coverage).
        c = []
        for set_cookie_header in self.headers.get_all("set-cookie"):
            try:
                refreshed = cookies.refresh_set_cookie_header(set_cookie_header, delta)
            except ValueError:
                refreshed = set_cookie_header
            c.append(refreshed)
        if c:
            self.headers.set_all("set-cookie", c)


class HTTPFlow(flow.Flow):
    """
    An HTTPFlow is a collection of objects representing a single HTTP
    transaction.
    """

    request: Request
    """The client's HTTP request."""
    response: Response | None = None
    """The server's HTTP response."""
    error: flow.Error | None = None
    """
    A connection or protocol error affecting this flow.

    Note that it's possible for a Flow to have both a response and an error
    object. This might happen, for instance, when a response was received
    from the server, but there was an error sending it back to the client.
    """

    websocket: WebSocketData | None = None
    """
    If this HTTP flow initiated a WebSocket connection, this attribute contains all associated WebSocket data.
    """

    def get_state(self) -> serializable.State:
        """
        导出 HTTPFlow 的可序列化状态。

        在基础 Flow 状态之外，额外保存 request、response 和 websocket 数据。
        response/websocket 可能不存在，因此按需写入 None。
        """
        return {
            **super().get_state(),
            "request": self.request.get_state(),
            "response": self.response.get_state() if self.response else None,
            "websocket": self.websocket.get_state() if self.websocket else None,
        }

    def set_state(self, state: serializable.State) -> None:
        """
        从序列化状态恢复 HTTPFlow。
        """
        self.request = Request.from_state(state.pop("request"))
        self.response = Response.from_state(r) if (r := state.pop("response")) else None
        self.websocket = (
            WebSocketData.from_state(w) if (w := state.pop("websocket")) else None
        )
        super().set_state(state)

    def __repr__(self):
        """
        返回包含主要字段的多行调试表示。
        """
        s = "<HTTPFlow"
        for a in (
            "request",
            "response",
            "websocket",
            "error",
            "client_conn",
            "server_conn",
        ):
            if getattr(self, a, False):
                s += f"\r\n  {a} = {{flow.{a}}}"
        s += ">"
        return s.format(flow=self)

    @property
    def timestamp_start(self) -> float:
        """*Read-only:* An alias for `Request.timestamp_start`."""
        return self.request.timestamp_start

    @property
    def mode(self) -> str:  # pragma: no cover
        """
        兼容旧 API 的代理模式属性。

        该属性已废弃，新代码应从连接或代理模式上下文获取相关信息。
        """
        warnings.warn("HTTPFlow.mode is deprecated.", DeprecationWarning, stacklevel=2)
        return getattr(self, "_mode", "regular")

    @mode.setter
    def mode(self, val: str) -> None:  # pragma: no cover
        """
        设置兼容旧 API 的代理模式属性。
        """
        warnings.warn("HTTPFlow.mode is deprecated.", DeprecationWarning, stacklevel=2)
        self._mode = val

    def copy(self):
        """
        深拷贝 HTTPFlow，并确保请求和响应对象也被复制。
        """
        f = super().copy()
        if self.request:
            f.request = self.request.copy()
        if self.response:
            f.response = self.response.copy()
        return f


__all__ = [
    "HTTPFlow",
    "Message",
    "Request",
    "Response",
    "Headers",
]
