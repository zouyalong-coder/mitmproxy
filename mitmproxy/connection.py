"""
客户端连接与上游服务器连接的元数据模型。

mitmproxy 的真实 socket I/O 由代理服务器层处理，本模块只保存连接的可见
状态：地址、传输协议、TLS 协商结果、时间戳、错误标记等。Flow 会引用这里
的 `Client` 和 `Server`，从而把一次协议交互和底层连接生命周期关联起来。
"""

import dataclasses
import time
import uuid
import warnings
from abc import ABCMeta
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from enum import Flag
from typing import Literal

from mitmproxy import certs
from mitmproxy.coretypes import serializable
from mitmproxy.net import server_spec
from mitmproxy.proxy import mode_specs
from mitmproxy.utils import human


class ConnectionState(Flag):
    """
    The current state of the underlying socket.

    中文说明：用位标志描述底层 socket 是否还能读、还能写。`OPEN` 是
    `CAN_READ | CAN_WRITE`，关闭态则两个方向都不可用。
    """

    CLOSED = 0
    CAN_READ = 1
    CAN_WRITE = 2
    OPEN = CAN_READ | CAN_WRITE


TransportProtocol = Literal["tcp", "udp"]

# https://docs.openssl.org/master/man3/SSL_get_version/#return-values
TlsVersion = Literal[
    "SSLv3",
    "TLSv1",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
    "DTLSv0.9",
    "DTLSv1",
    "DTLSv1.2",
    "QUICv1",
]

# practically speaking we may have IPv6 addresses with flowinfo and scope_id,
# but type checking isn't good enough to properly handle tuple unions.
# this version at least provides useful type checking messages.
Address = tuple[str, int]


@dataclass(kw_only=True)
class Connection(serializable.SerializableDataclass, metaclass=ABCMeta):
    """
    Base class for client and server connections.

    The connection object only exposes metadata about the connection, but not the underlying socket object.
    This is intentional, all I/O should be handled by `mitmproxy.proxy.server` exclusively.

    中文说明：连接对象是“状态快照”，不是 socket 包装器。这样脚本和 UI 可以
    安全读取连接元数据，而不会绕过代理层的事件调度和流控。
    """

    peername: Address | None
    """The remote's `(ip, port)` tuple for this connection."""
    sockname: Address | None
    """Our local `(ip, port)` tuple for this connection."""

    state: ConnectionState = field(
        default=ConnectionState.CLOSED, metadata={"serialize": False}
    )
    """
    The current connection state.

    中文说明：运行期状态不参与序列化，历史 flow 从文件恢复时不会假装连接仍然
    打开；是否存活由当前代理进程负责判断。
    """

    # all connections have a unique id. While
    # f.client_conn == f2.client_conn already holds true for live flows (where we have object identity),
    # we also want these semantics for recorded flows.
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """
    A unique UUID to identify the connection.

    中文说明：实时 flow 可以靠对象身份比较连接，但录制/回放的 flow 需要稳定
    ID 来表达“这是同一条连接”。
    """
    transport_protocol: TransportProtocol = field(default="tcp")
    """The connection protocol in use."""
    error: str | None = None
    """
    A string describing a general error with connections to this address.

    The purpose of this property is to signal that new connections to the particular endpoint should not be attempted,
    for example because it uses an untrusted TLS certificate. Regular (unexpected) disconnects do not set the error
    property. This property is only reused per client connection.
    """

    tls: bool = False
    """
    `True` if TLS should be established, `False` otherwise.
    Note that this property only describes if a connection should eventually be protected using TLS.
    To check if TLS has already been established, use `Connection.tls_established`.
    """
    certificate_list: Sequence[certs.Cert] = ()
    """
    The TLS certificate list as sent by the peer.
    The first certificate is the end-entity certificate.

    > [RFC 8446] Prior to TLS 1.3, "certificate_list" ordering required each
    > certificate to certify the one immediately preceding it; however,
    > some implementations allowed some flexibility.  Servers sometimes
    > send both a current and deprecated intermediate for transitional
    > purposes, and others are simply configured incorrectly, but these
    > cases can nonetheless be validated properly.  For maximum
    > compatibility, all implementations SHOULD be prepared to handle
    > potentially extraneous certificates and arbitrary orderings from any
    > TLS version, with the exception of the end-entity certificate which
    > MUST be first.
    """
    alpn: bytes | None = None
    """The application-layer protocol as negotiated using
    [ALPN](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation)."""
    alpn_offers: Sequence[bytes] = ()
    """The ALPN offers as sent in the ClientHello."""
    # we may want to add SSL_CIPHER_description here, but that's currently not exposed by cryptography
    cipher: str | None = None
    """The active cipher name as returned by OpenSSL's `SSL_CIPHER_get_name`."""
    cipher_list: Sequence[str] = ()
    """Ciphers accepted by the proxy server on this connection."""
    tls_version: TlsVersion | None = None
    """The active TLS version."""
    sni: str | None = None
    """
    The [Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) sent in the ClientHello.
    """

    timestamp_start: float | None = None
    timestamp_end: float | None = None
    """*Timestamp:* Connection has been closed."""
    timestamp_tls_setup: float | None = None
    """*Timestamp:* TLS handshake has been completed successfully."""

    @property
    def connected(self) -> bool:
        """*Read-only:* `True` if Connection.state is ConnectionState.OPEN, `False` otherwise."""
        return self.state is ConnectionState.OPEN

    @property
    def tls_established(self) -> bool:
        """*Read-only:* `True` if TLS has been established, `False` otherwise."""
        return self.timestamp_tls_setup is not None

    def __eq__(self, other):
        if isinstance(other, Connection):
            return self.id == other.id
        return False

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        attrs = {
            # ensure these come first.
            "id": None,
            "address": None,
        }
        for f in dataclasses.fields(self):
            val = getattr(self, f.name)
            if val != f.default:
                if f.name == "cipher_list":
                    val = f"<{len(val)} ciphers>"
                elif f.name == "id":
                    val = f"…{val[-6:]}"
                attrs[f.name] = val
        return f"{type(self).__name__}({attrs!r})"

    @property
    def alpn_proto_negotiated(self) -> bytes | None:  # pragma: no cover
        """*Deprecated:* An outdated alias for Connection.alpn."""
        warnings.warn(
            "Connection.alpn_proto_negotiated is deprecated, use Connection.alpn instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.alpn


@dataclass(eq=False, repr=False, kw_only=True)
class Client(Connection):  # type: ignore[override]
    """
    A connection between a client and mitmproxy.

    中文说明：表示下游客户端到 mitmproxy 的半边连接，记录客户端地址、监听
    地址、代理模式和 mitmproxy 给客户端使用的证书。
    """

    peername: Address
    """The client's address."""
    sockname: Address
    """The local address we received this connection on."""

    mitmcert: certs.Cert | None = None
    """
    The certificate used by mitmproxy to establish TLS with the client.
    """

    proxy_mode: mode_specs.ProxyMode = field(
        default=mode_specs.ProxyMode.parse("regular")
    )
    """The proxy server type this client has been connecting to."""

    timestamp_start: float = field(default_factory=time.time)
    """*Timestamp:* TCP SYN received"""

    def __str__(self):
        if self.alpn:
            tls_state = f", alpn={self.alpn.decode(errors='replace')}"
        elif self.tls_established:
            tls_state = ", tls"
        else:
            tls_state = ""
        state = self.state.name
        assert state
        return f"Client({human.format_address(self.peername)}, state={state.lower()}{tls_state})"

    @property
    def address(self):  # pragma: no cover
        """*Deprecated:* An outdated alias for Client.peername."""
        warnings.warn(
            "Client.address is deprecated, use Client.peername instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.peername

    @address.setter
    def address(self, x):  # pragma: no cover
        warnings.warn(
            "Client.address is deprecated, use Client.peername instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.peername = x

    @property
    def cipher_name(self) -> str | None:  # pragma: no cover
        """*Deprecated:* An outdated alias for Connection.cipher."""
        warnings.warn(
            "Client.cipher_name is deprecated, use Client.cipher instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.cipher

    @property
    def clientcert(self) -> certs.Cert | None:  # pragma: no cover
        """*Deprecated:* An outdated alias for Connection.certificate_list[0]."""
        warnings.warn(
            "Client.clientcert is deprecated, use Client.certificate_list instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if self.certificate_list:
            return self.certificate_list[0]
        else:
            return None

    @clientcert.setter
    def clientcert(self, val):  # pragma: no cover
        warnings.warn(
            "Client.clientcert is deprecated, use Client.certificate_list instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if val:
            self.certificate_list = [val]
        else:
            self.certificate_list = []


@dataclass(eq=False, repr=False, kw_only=True)
class Server(Connection):
    """
    A connection between mitmproxy and an upstream server.

    中文说明：表示 mitmproxy 到真实上游或上游代理的半边连接。`address` 是
    逻辑目标，`peername` 是解析并实际连接到的地址，两者在透明代理、显式代理
    和上游代理模式下可能不同。
    """

    address: Address | None  # type: ignore
    """
    The server's `(host, port)` address tuple.

    The host can either be a domain or a plain IP address.
    Which of those two will be present depends on the proxy mode and the client.
    For explicit proxies, this value will reflect what the client instructs mitmproxy to connect to.
    For example, if the client starts off a connection with `CONNECT example.com HTTP/1.1`, it will be `example.com`.
    For transparent proxies such as WireGuard mode, this value will be an IP address.
    """

    peername: Address | None = None
    """
    The server's resolved `(ip, port)` tuple. Will be set during connection establishment.
    May be `None` in upstream proxy mode when the address is resolved by the upstream proxy only.
    """
    sockname: Address | None = None

    timestamp_start: float | None = None
    """
    *Timestamp:* Connection establishment started.

    For IP addresses, this corresponds to sending a TCP SYN; for domains, this corresponds to starting a DNS lookup.
    """
    timestamp_tcp_setup: float | None = None
    """*Timestamp:* TCP ACK received."""

    via: server_spec.ServerSpec | None = None
    """An optional proxy server specification via which the connection should be established."""

    def __str__(self):
        if self.alpn:
            tls_state = f", alpn={self.alpn.decode(errors='replace')}"
        elif self.tls_established:
            tls_state = ", tls"
        else:
            tls_state = ""
        if self.sockname:
            local_port = f", src_port={self.sockname[1]}"
        else:
            local_port = ""
        state = self.state.name
        assert state
        return f"Server({human.format_address(self.address)}, state={state.lower()}{tls_state}{local_port})"

    def __setattr__(self, name, value):
        """
        防止在连接打开后修改会改变路由语义的字段。

        `address` 和 `via` 决定连接目标及是否经过上游代理；一旦 socket 已经
        打开，再修改它们会让状态和真实连接不一致，所以这里直接拒绝。
        """
        if name in ("address", "via"):
            connection_open = (
                self.__dict__.get("state", ConnectionState.CLOSED)
                is ConnectionState.OPEN
            )
            # assigning the current value is okay, that may be an artifact of calling .set_state().
            attr_changed = self.__dict__.get(name) != value
            if connection_open and attr_changed:
                raise RuntimeError(f"Cannot change server.{name} on open connection.")
        return super().__setattr__(name, value)

    @property
    def ip_address(self) -> Address | None:  # pragma: no cover
        """*Deprecated:* An outdated alias for `Server.peername`."""
        warnings.warn(
            "Server.ip_address is deprecated, use Server.peername instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.peername

    @property
    def cert(self) -> certs.Cert | None:  # pragma: no cover
        """*Deprecated:* An outdated alias for `Connection.certificate_list[0]`."""
        warnings.warn(
            "Server.cert is deprecated, use Server.certificate_list instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if self.certificate_list:
            return self.certificate_list[0]
        else:
            return None

    @cert.setter
    def cert(self, val):  # pragma: no cover
        warnings.warn(
            "Server.cert is deprecated, use Server.certificate_list instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if val:
            self.certificate_list = [val]
        else:
            self.certificate_list = []


__all__ = ["Connection", "Client", "Server", "ConnectionState"]
