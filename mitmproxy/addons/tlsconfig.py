"""
为代理核心提供 TLS/DTLS/QUIC 握手配置的内置 addon。

触发点：
- `load`：注册 TLS 版本、曲线、cipher、客户端证书请求等选项。
- `tls_clienthello`：客户端 ClientHello 到达时触发，决定是否先连上游。
- `tls_start_client/tls_start_server`：TLS/DTLS 握手开始时触发，创建 pyOpenSSL 连接对象。
- `quic_start_client/quic_start_server`：QUIC TLS 配置开始时触发，填充 aioquic 设置。
- `running/configure`：初始化/更新证书库并校验 TLS 相关选项。
- `request`：拦截特殊 CRL URL，请求 mitmproxy 生成的 CRL 文件。
"""

import ipaddress
import logging
import os
import ssl
import urllib.parse
from pathlib import Path
from typing import Any
from typing import Literal
from typing import TypedDict

from aioquic.h3.connection import H3_ALPN
from aioquic.tls import CipherSuite
from cryptography import x509
from OpenSSL import SSL

from mitmproxy import certs
from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import tls
from mitmproxy.net import tls as net_tls
from mitmproxy.options import CONF_BASENAME
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers import quic
from mitmproxy.proxy.layers import tls as proxy_tls

logger = logging.getLogger(__name__)

# We manually need to specify this, otherwise OpenSSL may select a non-HTTP2 cipher by default.
# https://ssl-config.mozilla.org/#config=old

_DEFAULT_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA256",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
)

_DEFAULT_CIPHERS_WITH_SECLEVEL_0 = ("@SECLEVEL=0", *_DEFAULT_CIPHERS)


def _default_ciphers(
    min_tls_version: net_tls.Version,
) -> tuple[str, ...]:
    """
    @SECLEVEL=0 is necessary for TLS 1.1 and below to work,
    see https://github.com/pyca/cryptography/issues/9523
    
    中文说明：低版本 TLS 需要 OpenSSL security level 0 才能正常使用，因此当最小
    TLS 版本不安全时自动在默认 cipher 列表前加 `@SECLEVEL=0`。
    """
    if min_tls_version in net_tls.INSECURE_TLS_MIN_VERSIONS:
        return _DEFAULT_CIPHERS_WITH_SECLEVEL_0
    else:
        return _DEFAULT_CIPHERS


# 2022/05: X509_CHECK_FLAG_NEVER_CHECK_SUBJECT is not available in LibreSSL, ignore gracefully as it's not critical.
DEFAULT_HOSTFLAGS = (
    SSL._lib.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS  # type: ignore
    | getattr(SSL._lib, "X509_CHECK_FLAG_NEVER_CHECK_SUBJECT", 0)  # type: ignore
)


class AppData(TypedDict):
    """
    保存 TLS ALPN 协商回调所需的上下文数据。
    """
    client_alpn: bytes | None
    server_alpn: bytes | None
    http2: bool


def alpn_select_callback(conn: SSL.Connection, options: list[bytes]) -> Any:
    """
    根据客户端和上游服务器的 ALPN 信息选择最终协商协议。
    """
    app_data: AppData = conn.get_app_data()
    client_alpn = app_data["client_alpn"]
    server_alpn = app_data["server_alpn"]
    http2 = app_data["http2"]
    if client_alpn is not None:
        if client_alpn in options:
            return client_alpn
        else:
            return SSL.NO_OVERLAPPING_PROTOCOLS
    if server_alpn and server_alpn in options:
        return server_alpn
    if server_alpn == b"":
        # We do have a server connection, but the remote server refused to negotiate a protocol:
        # We need to mirror this on the client connection.
        return SSL.NO_OVERLAPPING_PROTOCOLS
    http_alpns = proxy_tls.HTTP_ALPNS if http2 else proxy_tls.HTTP1_ALPNS
    # client sends in order of preference, so we are nice and respect that.
    for alpn in options:
        if alpn in http_alpns:
            return alpn
    else:
        return SSL.NO_OVERLAPPING_PROTOCOLS


class TlsConfig:
    """
    This addon supplies the proxy core with the desired OpenSSL connection objects to negotiate TLS.
    
    中文说明：TLSConfig 是 TLS 拦截的配置中心，负责证书选择、上下游 TLS
    context 创建、ALPN 镜像、SNI/证书校验和 QUIC TLS 参数。
    """

    certstore: certs.CertStore = None  # type: ignore

    # TODO: We should support configuring TLS 1.3 cipher suites (https://github.com/mitmproxy/mitmproxy/issues/4260)
    # TODO: We should re-use SSL.Context options here, if only for TLS session resumption.
    #       This may require patches to pyOpenSSL, as some functionality is only exposed on contexts.
    # TODO: This addon should manage the following options itself, which are current defined in mitmproxy/options.py:
    #  - upstream_cert
    #  - add_upstream_certs_to_client_chain
    #  - key_size
    #  - certs
    #  - cert_passphrase
    #  - ssl_verify_upstream_trusted_ca
    #  - ssl_verify_upstream_trusted_confdir

    def load(self, loader):
        """
        addon 加载事件：注册 TLS/DTLS/QUIC 握手相关选项。
        """
        insecure_tls_min_versions = (
            ", ".join(x.name for x in net_tls.INSECURE_TLS_MIN_VERSIONS[:-1])
            + f" and {net_tls.INSECURE_TLS_MIN_VERSIONS[-1].name}"
        )
        loader.add_option(
            name="tls_version_client_min",
            typespec=str,
            default=net_tls.DEFAULT_MIN_VERSION.name,
            choices=[x.name for x in net_tls.Version],
            help=f"Set the minimum TLS version for client connections. "
            f"{insecure_tls_min_versions} are insecure.",
        )
        loader.add_option(
            name="tls_version_client_max",
            typespec=str,
            default=net_tls.DEFAULT_MAX_VERSION.name,
            choices=[x.name for x in net_tls.Version],
            help=f"Set the maximum TLS version for client connections.",
        )
        loader.add_option(
            name="tls_version_server_min",
            typespec=str,
            default=net_tls.DEFAULT_MIN_VERSION.name,
            choices=[x.name for x in net_tls.Version],
            help=f"Set the minimum TLS version for server connections. "
            f"{insecure_tls_min_versions} are insecure.",
        )
        loader.add_option(
            name="tls_version_server_max",
            typespec=str,
            default=net_tls.DEFAULT_MAX_VERSION.name,
            choices=[x.name for x in net_tls.Version],
            help=f"Set the maximum TLS version for server connections.",
        )
        loader.add_option(
            name="tls_ecdh_curve_client",
            typespec=str | None,
            default=None,
            help="Use a specific elliptic curve for ECDHE key exchange on client connections. "
            'OpenSSL syntax, for example "prime256v1" (see `openssl ecparam -list_curves`).',
        )
        loader.add_option(
            name="tls_ecdh_curve_server",
            typespec=str | None,
            default=None,
            help="Use a specific elliptic curve for ECDHE key exchange on server connections. "
            'OpenSSL syntax, for example "prime256v1" (see `openssl ecparam -list_curves`).',
        )
        loader.add_option(
            name="request_client_cert",
            typespec=bool,
            default=False,
            help=f"Requests a client certificate (TLS message 'CertificateRequest') to establish a mutual TLS connection between client and mitmproxy (combined with 'client_certs' option for mitmproxy and upstream).",
        )
        loader.add_option(
            "ciphers_client",
            str | None,
            None,
            "Set supported ciphers for client <-> mitmproxy connections using OpenSSL syntax.",
        )
        loader.add_option(
            "ciphers_server",
            str | None,
            None,
            "Set supported ciphers for mitmproxy <-> server connections using OpenSSL syntax.",
        )

    def tls_clienthello(self, tls_clienthello: tls.ClientHelloData):
        """
        `tls_clienthello` 事件：客户端 ClientHello 解析完成后触发。

        eager 连接策略下会要求先和上游建立 TLS，以便用真实上游证书生成更贴近
        目标站点的拦截证书。
        """
        conn_context = tls_clienthello.context
        tls_clienthello.establish_server_tls_first = (
            conn_context.server.tls and ctx.options.connection_strategy == "eager"
        )

    def tls_start_client(self, tls_start: tls.TlsData) -> None:
        """
        Establish TLS or DTLS between client and proxy.
        
        中文说明：`tls_start_client` 事件，为客户端到 mitmproxy 的 TLS/DTLS
        连接创建服务端 SSL.Connection，并加载动态生成的证书和私钥。
        """
        if tls_start.ssl_conn is not None:
            return  # a user addon has already provided the pyOpenSSL context.

        assert isinstance(tls_start.conn, connection.Client)

        client: connection.Client = tls_start.conn
        server: connection.Server = tls_start.context.server

        entry = self.get_cert(tls_start.context)

        if not client.cipher_list and ctx.options.ciphers_client:
            client.cipher_list = ctx.options.ciphers_client.split(":")
        # don't assign to client.cipher_list, doesn't need to be stored.
        cipher_list = client.cipher_list or _default_ciphers(
            net_tls.Version[ctx.options.tls_version_client_min]
        )

        if ctx.options.add_upstream_certs_to_client_chain:  # pragma: no cover
            # exempted from coverage until https://bugs.python.org/issue18233 is fixed.
            extra_chain_certs = server.certificate_list
        else:
            extra_chain_certs = []

        ssl_ctx = net_tls.create_client_proxy_context(
            method=net_tls.Method.DTLS_SERVER_METHOD
            if tls_start.is_dtls
            else net_tls.Method.TLS_SERVER_METHOD,
            min_version=net_tls.Version[ctx.options.tls_version_client_min],
            max_version=net_tls.Version[ctx.options.tls_version_client_max],
            cipher_list=tuple(cipher_list),
            ecdh_curve=net_tls.get_curve(ctx.options.tls_ecdh_curve_client),
            chain_file=entry.chain_file,
            request_client_cert=ctx.options.request_client_cert,
            alpn_select_callback=alpn_select_callback,
            extra_chain_certs=tuple(extra_chain_certs),
            dhparams=self.certstore.dhparams,
        )
        tls_start.ssl_conn = SSL.Connection(ssl_ctx)

        tls_start.ssl_conn.use_certificate(entry.cert.to_cryptography())
        tls_start.ssl_conn.use_privatekey(entry.privatekey)

        # Force HTTP/1 for secure web proxies, we currently don't support CONNECT over HTTP/2.
        # There is a proof-of-concept branch at https://github.com/mhils/mitmproxy/tree/http2-proxy,
        # but the complexity outweighs the benefits for now.
        if len(tls_start.context.layers) == 2 and isinstance(
            tls_start.context.layers[0], modes.HttpProxy
        ):
            client_alpn: bytes | None = b"http/1.1"
        else:
            client_alpn = client.alpn

        tls_start.ssl_conn.set_app_data(
            AppData(
                client_alpn=client_alpn,
                server_alpn=server.alpn,
                http2=ctx.options.http2,
            )
        )
        tls_start.ssl_conn.set_accept_state()

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        """
        Establish TLS or DTLS between proxy and server.
        
        中文说明：`tls_start_server` 事件，为 mitmproxy 到上游服务器的 TLS/DTLS
        连接创建客户端 SSL.Connection，并配置 SNI、ALPN、证书校验和客户端证书。
        """
        if tls_start.ssl_conn is not None:
            return  # a user addon has already provided the pyOpenSSL context.

        assert isinstance(tls_start.conn, connection.Server)

        client: connection.Client = tls_start.context.client
        # tls_start.conn may be different from tls_start.context.server, e.g. an upstream HTTPS proxy.
        server: connection.Server = tls_start.conn
        assert server.address

        if ctx.options.ssl_insecure:
            verify = net_tls.Verify.VERIFY_NONE
        else:
            verify = net_tls.Verify.VERIFY_PEER

        if server.sni is None:
            server.sni = client.sni or server.address[0]

        if not server.alpn_offers:
            if client.alpn_offers:
                if ctx.options.http2:
                    # We would perfectly support HTTP/1 -> HTTP/2, but we want to keep things on the same protocol
                    # version. There are some edge cases where we want to mirror the regular server's behavior
                    # accurately, for example header capitalization.
                    server.alpn_offers = tuple(client.alpn_offers)
                else:
                    server.alpn_offers = tuple(
                        x for x in client.alpn_offers if x != b"h2"
                    )
            else:
                # We either have no client TLS or a client without ALPN.
                # - If the client does use TLS but did not send an ALPN extension, we want to mirror that upstream.
                # - If the client does not use TLS, there's no clear-cut answer. As a pragmatic approach, we also do
                #   not send any ALPN extension in this case, which defaults to whatever protocol we are speaking
                #   or falls back to HTTP.
                server.alpn_offers = []

        if not server.cipher_list and ctx.options.ciphers_server:
            server.cipher_list = ctx.options.ciphers_server.split(":")
        # don't assign to client.cipher_list, doesn't need to be stored.
        cipher_list = server.cipher_list or _default_ciphers(
            net_tls.Version[ctx.options.tls_version_server_min]
        )

        client_cert: str | None = None
        if ctx.options.client_certs:
            client_certs = os.path.expanduser(ctx.options.client_certs)
            if os.path.isfile(client_certs):
                client_cert = client_certs
            else:
                server_name: str = server.sni or server.address[0]
                p = os.path.join(client_certs, f"{server_name}.pem")
                if os.path.isfile(p):
                    client_cert = p

        ssl_ctx = net_tls.create_proxy_server_context(
            method=net_tls.Method.DTLS_CLIENT_METHOD
            if tls_start.is_dtls
            else net_tls.Method.TLS_CLIENT_METHOD,
            min_version=net_tls.Version[ctx.options.tls_version_server_min],
            max_version=net_tls.Version[ctx.options.tls_version_server_max],
            cipher_list=tuple(cipher_list),
            ecdh_curve=net_tls.get_curve(ctx.options.tls_ecdh_curve_server),
            verify=verify,
            ca_path=ctx.options.ssl_verify_upstream_trusted_confdir,
            ca_pemfile=ctx.options.ssl_verify_upstream_trusted_ca,
            client_cert=client_cert,
            legacy_server_connect=ctx.options.ssl_insecure,
        )

        tls_start.ssl_conn = SSL.Connection(ssl_ctx)
        if server.sni:
            # We need to set SNI + enable hostname verification.
            assert isinstance(server.sni, str)
            # Manually enable hostname verification on the context object.
            # https://wiki.openssl.org/index.php/Hostname_validation
            param = SSL._lib.SSL_get0_param(tls_start.ssl_conn._ssl)  # type: ignore
            # Matching on the CN is disabled in both Chrome and Firefox, so we disable it, too.
            # https://www.chromestatus.com/feature/4981025180483584

            SSL._lib.X509_VERIFY_PARAM_set_hostflags(param, DEFAULT_HOSTFLAGS)  # type: ignore

            try:
                ip: bytes = ipaddress.ip_address(server.sni).packed
            except ValueError:
                host_name = server.sni.encode("idna")
                tls_start.ssl_conn.set_tlsext_host_name(host_name)
                ok = SSL._lib.X509_VERIFY_PARAM_set1_host(  # type: ignore
                    param, host_name, len(host_name)
                )  # type: ignore
                SSL._openssl_assert(ok == 1)  # type: ignore
            else:
                # RFC 6066: Literal IPv4 and IPv6 addresses are not permitted in "HostName",
                # so we don't call set_tlsext_host_name.
                ok = SSL._lib.X509_VERIFY_PARAM_set1_ip(param, ip, len(ip))  # type: ignore
                SSL._openssl_assert(ok == 1)  # type: ignore
        elif verify is not net_tls.Verify.VERIFY_NONE:
            raise ValueError("Cannot validate certificate hostname without SNI")

        if server.alpn_offers:
            tls_start.ssl_conn.set_alpn_protos(list(server.alpn_offers))

        tls_start.ssl_conn.set_connect_state()

    def quic_start_client(self, tls_start: quic.QuicTlsData) -> None:
        """
        Establish QUIC between client and proxy.
        
        中文说明：`quic_start_client` 事件，为客户端到 mitmproxy 的 QUIC TLS
        填充证书、私钥、ALPN 和 cipher 设置。
        """
        if tls_start.settings is not None:
            return  # a user addon has already provided the settings.
        tls_start.settings = quic.QuicTlsSettings()

        # keep the following part in sync with `tls_start_client`
        assert isinstance(tls_start.conn, connection.Client)

        client: connection.Client = tls_start.conn
        server: connection.Server = tls_start.context.server

        entry = self.get_cert(tls_start.context)

        if not client.cipher_list and ctx.options.ciphers_client:
            client.cipher_list = ctx.options.ciphers_client.split(":")

        if ctx.options.add_upstream_certs_to_client_chain:  # pragma: no cover
            extra_chain_certs = server.certificate_list
        else:
            extra_chain_certs = []

        # set context parameters
        if client.cipher_list:
            tls_start.settings.cipher_suites = [
                CipherSuite[cipher] for cipher in client.cipher_list
            ]
        # if we don't have upstream ALPN, we allow all offered by the client
        tls_start.settings.alpn_protocols = [
            alpn.decode("ascii")
            for alpn in [alpn for alpn in (client.alpn, server.alpn) if alpn]
            or client.alpn_offers
        ]

        # set the certificates
        tls_start.settings.certificate = entry.cert._cert
        tls_start.settings.certificate_private_key = entry.privatekey
        tls_start.settings.certificate_chain = [
            cert._cert for cert in (*entry.chain_certs, *extra_chain_certs)
        ]

    def quic_start_server(self, tls_start: quic.QuicTlsData) -> None:
        """
        Establish QUIC between proxy and server.
        
        中文说明：`quic_start_server` 事件，为 mitmproxy 到上游的 QUIC TLS
        填充校验策略、SNI、ALPN、CA 配置和 cipher 设置。
        """
        if tls_start.settings is not None:
            return  # a user addon has already provided the settings.
        tls_start.settings = quic.QuicTlsSettings()

        # keep the following part in sync with `tls_start_server`
        assert isinstance(tls_start.conn, connection.Server)

        client: connection.Client = tls_start.context.client
        server: connection.Server = tls_start.conn
        assert server.address

        if ctx.options.ssl_insecure:
            tls_start.settings.verify_mode = ssl.CERT_NONE
        else:
            tls_start.settings.verify_mode = ssl.CERT_REQUIRED

        if server.sni is None:
            server.sni = client.sni or server.address[0]

        if not server.alpn_offers:
            if client.alpn_offers:
                server.alpn_offers = tuple(client.alpn_offers)
            else:
                # aioquic fails if no ALPN is offered, so use H3
                server.alpn_offers = tuple(alpn.encode("ascii") for alpn in H3_ALPN)

        if not server.cipher_list and ctx.options.ciphers_server:
            server.cipher_list = ctx.options.ciphers_server.split(":")

        # set context parameters
        if server.cipher_list:
            tls_start.settings.cipher_suites = [
                CipherSuite[cipher] for cipher in server.cipher_list
            ]
        if server.alpn_offers:
            tls_start.settings.alpn_protocols = [
                alpn.decode("ascii") for alpn in server.alpn_offers
            ]

        # set the certificates
        # NOTE client certificates are not supported
        tls_start.settings.ca_path = ctx.options.ssl_verify_upstream_trusted_confdir
        tls_start.settings.ca_file = ctx.options.ssl_verify_upstream_trusted_ca

    def running(self):
        # FIXME: We have a weird bug where the contract for configure is not followed and it is never called with
        # confdir or command_history as updated.
        """
        `running` 事件：mitmproxy 启动完成后触发，确保按当前 confdir 初始化证书库。
        """
        self.configure("confdir")  # pragma: no cover

    def configure(self, updated):
        """
        `configure` 事件：TLS/证书相关选项变化后触发。

        这里加载或重建 CertStore，校验自定义证书、椭圆曲线、TLS 版本和 cipher
        security level。
        """
        if (
            "certs" in updated
            or "confdir" in updated
            or "key_size" in updated
            or "cert_passphrase" in updated
        ):
            certstore_path = os.path.expanduser(ctx.options.confdir)
            self.certstore = certs.CertStore.from_store(
                path=certstore_path,
                basename=CONF_BASENAME,
                key_size=ctx.options.key_size,
                passphrase=ctx.options.cert_passphrase.encode("utf8")
                if ctx.options.cert_passphrase
                else None,
            )
            if self.certstore.default_ca.has_expired():
                logger.warning(
                    "The mitmproxy certificate authority has expired!\n"
                    "Please delete all CA-related files in your ~/.mitmproxy folder.\n"
                    "The CA will be regenerated automatically after restarting mitmproxy.\n"
                    "See https://docs.mitmproxy.org/stable/concepts-certificates/ for additional help.",
                )

            for certspec in ctx.options.certs:
                parts = certspec.split("=", 1)
                if len(parts) == 1:
                    parts = ["*", parts[0]]

                cert = Path(parts[1]).expanduser()
                if not cert.exists():
                    raise exceptions.OptionsError(
                        f"Certificate file does not exist: {cert}"
                    )
                try:
                    self.certstore.add_cert_file(
                        parts[0],
                        cert,
                        passphrase=ctx.options.cert_passphrase.encode("utf8")
                        if ctx.options.cert_passphrase
                        else None,
                    )
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Invalid certificate format for {cert}: {e}"
                    ) from e

        if "tls_ecdh_curve_client" in updated or "tls_ecdh_curve_server" in updated:
            for ecdh_curve in [
                ctx.options.tls_ecdh_curve_client,
                ctx.options.tls_ecdh_curve_server,
            ]:
                if ecdh_curve is not None and ecdh_curve not in net_tls.EC_CURVES:
                    raise exceptions.OptionsError(
                        f"Invalid ECDH curve: {ecdh_curve!r}. Valid curves are: {', '.join(net_tls.EC_CURVES)}"
                    )

        if "tls_version_client_min" in updated:
            self._warn_unsupported_version("tls_version_client_min", True)
        if "tls_version_client_max" in updated:
            self._warn_unsupported_version("tls_version_client_max", False)
        if "tls_version_server_min" in updated:
            self._warn_unsupported_version("tls_version_server_min", True)
        if "tls_version_server_max" in updated:
            self._warn_unsupported_version("tls_version_server_max", False)
        if "tls_version_client_min" in updated or "ciphers_client" in updated:
            self._warn_seclevel_missing("client")
        if "tls_version_server_min" in updated or "ciphers_server" in updated:
            self._warn_seclevel_missing("server")

    def _warn_unsupported_version(self, attribute: str, warn_unbound: bool):
        """
        检查当前 OpenSSL 是否支持用户配置的 TLS 版本，并给出日志提示。
        """
        val = net_tls.Version[getattr(ctx.options, attribute)]
        supported_versions = [
            v for v in net_tls.Version if net_tls.is_supported_version(v)
        ]
        supported_versions_str = ", ".join(v.name for v in supported_versions)

        if val is net_tls.Version.UNBOUNDED:
            if warn_unbound:
                logger.info(
                    f"{attribute} has been set to {val.name}. Note that your "
                    f"OpenSSL build only supports the following TLS versions: {supported_versions_str}"
                )
        elif val not in supported_versions:
            logger.warning(
                f"{attribute} has been set to {val.name}, which is not supported by the current OpenSSL build. "
                f"The current build only supports the following versions: {supported_versions_str}"
            )

    def _warn_seclevel_missing(self, side: Literal["client", "server"]) -> None:
        """
        OpenSSL cipher spec need to specify @SECLEVEL for old TLS versions to work,
        see https://github.com/pyca/cryptography/issues/9523.
        
        中文说明：用户自定义 cipher 时不会自动加默认的 `@SECLEVEL=0`，所以这里
        在低 TLS 版本配置下提醒用户手动加入。
        """
        if side == "client":
            custom_ciphers = ctx.options.ciphers_client
            min_tls_version = ctx.options.tls_version_client_min
        else:
            custom_ciphers = ctx.options.ciphers_server
            min_tls_version = ctx.options.tls_version_server_min

        if (
            custom_ciphers
            and net_tls.Version[min_tls_version] in net_tls.INSECURE_TLS_MIN_VERSIONS
            and "@SECLEVEL=0" not in custom_ciphers
        ):
            logger.warning(
                f'With tls_version_{side}_min set to {min_tls_version}, ciphers_{side} must include "@SECLEVEL=0" '
                f"for insecure TLS versions to work."
            )

    def crl_path(self) -> str:
        """
        返回 mitmproxy 用于替换 CRL Distribution Point 的特殊路径。
        """
        return f"/mitmproxy-{self.certstore.default_ca.serial}.crl"

    def get_cert(self, conn_context: context.Context) -> certs.CertStoreEntry:
        """
        This function determines the Common Name (CN), Subject Alternative Names (SANs) and Organization Name
        our certificate should have and then fetches a matching cert from the certstore.
        
        中文说明：优先从上游证书复制 CN/SAN/组织名，再补充客户端 SNI、本地地址
        和目标地址，最后从 CertStore 获取或生成匹配证书。
        """
        altnames: list[x509.GeneralName] = []
        organization: str | None = None
        crl_distribution_point: str | None = None

        # Use upstream certificate if available.
        if ctx.options.upstream_cert and conn_context.server.certificate_list:
            upstream_cert: certs.Cert = conn_context.server.certificate_list[0]
            if upstream_cert.cn:
                altnames.append(_ip_or_dns_name(upstream_cert.cn))
            altnames.extend(upstream_cert.altnames)
            if upstream_cert.organization:
                organization = upstream_cert.organization

            # Replace original URL path with the CA cert serial number, which acts as a magic token
            if crls := upstream_cert.crl_distribution_points:
                try:
                    scheme, netloc, *_ = urllib.parse.urlsplit(crls[0])
                except ValueError:
                    logger.info(f"Failed to parse CRL URL: {crls[0]!r}")
                else:
                    # noinspection PyTypeChecker
                    crl_distribution_point = urllib.parse.urlunsplit(
                        (scheme, netloc, self.crl_path(), None, None)
                    )

        # Add SNI or our local IP address.
        if conn_context.client.sni:
            altnames.append(_ip_or_dns_name(conn_context.client.sni))
        else:
            altnames.append(_ip_or_dns_name(conn_context.client.sockname[0]))

        # If we already know of a server address, include that in the SANs as well.
        if conn_context.server.address:
            altnames.append(_ip_or_dns_name(conn_context.server.address[0]))

        # only keep first occurrence of each hostname
        altnames = list(dict.fromkeys(altnames))

        # RFC 2818: If a subjectAltName extension of type dNSName is present, that MUST be used as the identity.
        # In other words, the Common Name is irrelevant then.
        cn = next((str(x.value) for x in altnames), None)
        return self.certstore.get_cert(
            cn, altnames, organization, crl_distribution_point
        )

    def request(self, flow: http.HTTPFlow):
        """
        HTTP `request` 事件：请求发往上游前触发。

        如果请求路径命中特殊 CRL token，则直接返回 mitmproxy 的默认 CRL。
        """
        if not flow.live or flow.error or flow.response:
            return
        # Check if a request has a magic CRL token at the end
        if flow.request.path.endswith(self.crl_path()):
            flow.response = http.Response.make(
                200,
                self.certstore.default_crl,
                {"Content-Type": "application/pkix-crl"},
            )


def _ip_or_dns_name(val: str) -> x509.GeneralName:
    """
    Convert a string into either an x509.IPAddress or x509.DNSName object.
    
    中文说明：证书 SAN 需要区分 IPAddress 和 DNSName，这里把字符串转换为
    cryptography 的对应 GeneralName 类型。
    """
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        return x509.DNSName(val.encode("idna").decode())
    else:
        return x509.IPAddress(ip)
