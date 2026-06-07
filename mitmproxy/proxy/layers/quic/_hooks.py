"""
QUIC/TLS 握手 hook 数据结构。

QUIC 使用 TLS 1.3 完成加密参数和 ALPN 协商。本模块定义 start_client 和
start_server 阶段传给 addon 的数据对象，`tlsconfig` 等 addon 会在这些 hook
里填充证书、ALPN、CA、校验策略等设置。

触发点：
- `QuicLayer` 作为服务器面对客户端握手前触发 `QuicStartClientHook`。
- `QuicLayer` 作为客户端连接上游服务器前触发 `QuicStartServerHook`。
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from ssl import VerifyMode

from aioquic.tls import CipherSuite
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from mitmproxy.proxy import commands
from mitmproxy.tls import TlsData


@dataclass
class QuicTlsSettings:
    """
    Settings necessary to establish QUIC's TLS context.

    中文说明：这些字段最终会转换为 aioquic 的 TLS/QUIC 配置。
    """

    alpn_protocols: list[str] | None = None
    """A list of supported ALPN protocols."""
    certificate: x509.Certificate | None = None
    """The certificate to use for the connection."""
    certificate_chain: list[x509.Certificate] = field(default_factory=list)
    """A list of additional certificates to send to the peer."""
    certificate_private_key: (
        dsa.DSAPrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None
    ) = None
    """The certificate's private key."""
    cipher_suites: list[CipherSuite] | None = None
    """An optional list of allowed/advertised cipher suites."""
    ca_path: str | None = None
    """An optional path to a directory that contains the necessary information to verify the peer certificate."""
    ca_file: str | None = None
    """An optional path to a PEM file that will be used to verify the peer certificate."""
    verify_mode: VerifyMode | None = None
    """An optional flag that specifies how/if the peer's certificate should be validated."""


@dataclass
class QuicTlsData(TlsData):
    """
    Event data for `quic_start_client` and `quic_start_server` event hooks.

    中文说明：继承通用 TLS hook 数据，并额外携带 QUIC 专用 TLS 设置。
    """

    settings: QuicTlsSettings | None = None
    """
    The associated `QuicTlsSettings` object.
    This will be set by an addon in the `quic_start_*` event hooks.
    """


@dataclass
class QuicStartClientHook(commands.StartHook):
    """
    TLS negotiation between mitmproxy and a client over QUIC is about to start.

    An addon is expected to initialize data.settings.
    (by default, this is done by `mitmproxy.addons.tlsconfig`)

    中文说明：mitmproxy 接受客户端 QUIC 握手前触发。
    """

    data: QuicTlsData


@dataclass
class QuicStartServerHook(commands.StartHook):
    """
    TLS negotiation between mitmproxy and a server over QUIC is about to start.

    An addon is expected to initialize data.settings.
    (by default, this is done by `mitmproxy.addons.tlsconfig`)

    中文说明：mitmproxy 连接上游 QUIC 服务器前触发。
    """

    data: QuicTlsData
