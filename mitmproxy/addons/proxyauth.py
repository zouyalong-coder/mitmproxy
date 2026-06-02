"""
`mitmproxy.addons.proxyauth` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from __future__ import annotations

import binascii
import pathlib
import weakref
from abc import ABC
from abc import abstractmethod
from collections.abc import MutableMapping
from typing import Optional

import ldap3

from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy.net.http import status_codes
from mitmproxy.proxy import mode_specs
from mitmproxy.proxy.layers import modes
from mitmproxy.utils import htpasswd

REALM = "mitmproxy"


class ProxyAuth:
    """
    `proxyauth` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    validator: Validator | None = None

    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.authenticated: MutableMapping[connection.Client, tuple[str, str]] = (
            weakref.WeakKeyDictionary()
        )
        """Contains all connections that are permanently authenticated after an HTTP CONNECT"""

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "proxyauth",
            Optional[str],
            None,
            """
            Require proxy authentication. Format:
            "username:pass",
            "any" to accept any user/pass combination,
            "@path" to use an Apache htpasswd file,
            or "ldap[s]:url_server_ldap[:port]:dn_auth:password:dn_subtree[?search_filter_key=...]" for LDAP authentication.
            """,
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "proxyauth" in updated:
            auth = ctx.options.proxyauth
            if auth:
                if auth == "any":
                    self.validator = AcceptAll()
                elif auth.startswith("@"):
                    self.validator = Htpasswd(auth)
                elif ctx.options.proxyauth.startswith("ldap"):
                    self.validator = Ldap(auth)
                elif ":" in ctx.options.proxyauth:
                    self.validator = SingleUser(auth)
                else:
                    raise exceptions.OptionsError("Invalid proxyauth specification.")
            else:
                self.validator = None

    def socks5_auth(self, data: modes.Socks5AuthData) -> None:
        """
        处理 SOCKS5 用户名/密码认证事件。
        """
        if self.validator and self.validator(data.username, data.password):
            data.valid = True
            self.authenticated[data.client_conn] = data.username, data.password

    def http_connect(self, f: http.HTTPFlow) -> None:
        """
        处理客户端发来的 HTTP CONNECT 代理指令。
        """
        if self.validator and self.authenticate_http(f):
            # Make a note that all further requests over this connection are ok.
            self.authenticated[f.client_conn] = f.metadata["proxyauth"]

    def requestheaders(self, f: http.HTTPFlow) -> None:
        """
        处理 HTTP 请求头事件，适合在 body 读取前决定流式处理或改写头部。
        """
        if self.validator:
            # Is this connection authenticated by a previous HTTP CONNECT?
            if f.client_conn in self.authenticated:
                f.metadata["proxyauth"] = self.authenticated[f.client_conn]
            elif f.is_replay:
                pass
            else:
                self.authenticate_http(f)

    def authenticate_http(self, f: http.HTTPFlow) -> bool:
        """
        Authenticate an HTTP request, returns if authentication was successful.

        If valid credentials are found, the matching authentication header is removed.
        In no or invalid credentials are found, flow.response is set to an error page.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        assert self.validator
        username = None
        password = None
        is_valid = False

        is_proxy = is_http_proxy(f)
        auth_header = http_auth_header(is_proxy)
        try:
            auth_value = f.request.headers.get(auth_header, "")
            scheme, username, password = parse_http_basic_auth(auth_value)
            is_valid = self.validator(username, password)
        except Exception:
            pass

        if is_valid:
            f.metadata["proxyauth"] = (username, password)
            del f.request.headers[auth_header]
            return True
        else:
            f.response = make_auth_required_response(is_proxy)
            return False


def make_auth_required_response(is_proxy: bool) -> http.Response:
    """
    构造代理认证失败时返回给客户端的 HTTP 响应。
    """
    if is_proxy:
        status_code = status_codes.PROXY_AUTH_REQUIRED
        headers = {"Proxy-Authenticate": f'Basic realm="{REALM}"'}
    else:
        status_code = status_codes.UNAUTHORIZED
        headers = {"WWW-Authenticate": f'Basic realm="{REALM}"'}

    reason = http.status_codes.RESPONSES[status_code]
    return http.Response.make(
        status_code,
        (
            f"<html>"
            f"<head><title>{status_code} {reason}</title></head>"
            f"<body><h1>{status_code} {reason}</h1></body>"
            f"</html>"
        ),
        headers,
    )


def http_auth_header(is_proxy: bool) -> str:
    """
    读取当前 flow 中用于代理认证的 HTTP 头。
    """
    if is_proxy:
        return "Proxy-Authorization"
    else:
        return "Authorization"


def is_http_proxy(f: http.HTTPFlow) -> bool:
    """
    Returns:
        - True, if authentication is done as if mitmproxy is a proxy
        - False, if authentication is done as if mitmproxy is an HTTP server
    
    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
    """
    return isinstance(
        f.client_conn.proxy_mode, (mode_specs.RegularMode, mode_specs.UpstreamMode)
    )


def mkauth(username: str, password: str, scheme: str = "basic") -> str:
    """
    Craft a basic auth string
    
    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
    """
    v = binascii.b2a_base64((username + ":" + password).encode("utf8")).decode("ascii")
    return scheme + " " + v


def parse_http_basic_auth(s: str) -> tuple[str, str, str]:
    """
    Parse a basic auth header.
    Raises a ValueError if the input is invalid.
    
    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
    """
    scheme, authinfo = s.split()
    if scheme.lower() != "basic":
        raise ValueError("Unknown scheme")
    try:
        user, password = (
            binascii.a2b_base64(authinfo.encode()).decode("utf8", "replace").split(":")
        )
    except binascii.Error as e:
        raise ValueError(str(e))
    return scheme, user, password


class Validator(ABC):
    """
    Base class for all username/password validators.
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    @abstractmethod
    def __call__(self, username: str, password: str) -> bool:
        """
        让对象可以像函数一样被调用。
        """
        raise NotImplementedError


class AcceptAll(Validator):
    """
    接受任意代理认证凭据的认证器。
    """
    def __call__(self, username: str, password: str) -> bool:
        """
        让对象可以像函数一样被调用。
        """
        return True


class SingleUser(Validator):
    """
    校验单个用户名和密码的认证器。
    """
    def __init__(self, proxyauth: str):
        """
        初始化对象状态。
        """
        try:
            self.username, self.password = proxyauth.split(":")
        except ValueError:
            raise exceptions.OptionsError("Invalid single-user auth specification.")

    def __call__(self, username: str, password: str) -> bool:
        """
        让对象可以像函数一样被调用。
        """
        return self.username == username and self.password == password


class Htpasswd(Validator):
    """
    基于 htpasswd 文件校验代理认证的认证器。
    """
    def __init__(self, proxyauth: str):
        """
        初始化对象状态。
        """
        path = pathlib.Path(proxyauth[1:]).expanduser()
        try:
            self.htpasswd = htpasswd.HtpasswdFile.from_file(path)
        except (ValueError, OSError) as e:
            raise exceptions.OptionsError(
                f"Could not open htpasswd file: {path}"
            ) from e

    def __call__(self, username: str, password: str) -> bool:
        """
        让对象可以像函数一样被调用。
        """
        return self.htpasswd.check_password(username, password)


class Ldap(Validator):
    """
    基于 LDAP 查询校验代理认证的认证器。
    """
    conn: ldap3.Connection
    server: ldap3.Server
    dn_subtree: str
    filter_key: str

    def __init__(self, proxyauth: str):
        """
        初始化对象状态。
        """
        (
            use_ssl,
            url,
            port,
            ldap_user,
            ldap_pass,
            self.dn_subtree,
            self.filter_key,
        ) = self.parse_spec(proxyauth)
        server = ldap3.Server(url, port=port, use_ssl=use_ssl)
        conn = ldap3.Connection(server, ldap_user, ldap_pass, auto_bind=True)
        self.conn = conn
        self.server = server

    @staticmethod
    def parse_spec(spec: str) -> tuple[bool, str, int | None, str, str, str, str]:
        """
        解析用户配置字符串并构造对应的运行时校验器或规则对象。
        """
        try:
            if spec.count(":") > 4:
                (
                    security,
                    url,
                    port_str,
                    ldap_user,
                    ldap_pass,
                    dn_subtree,
                ) = spec.split(":")
                port = int(port_str)
            else:
                security, url, ldap_user, ldap_pass, dn_subtree = spec.split(":")
                port = None

            if "?" in dn_subtree:
                dn_subtree, search_str = dn_subtree.split("?")
                key, value = search_str.split("=")
                if key == "search_filter_key":
                    search_filter_key = value
                else:
                    raise ValueError
            else:
                search_filter_key = "cn"

            if security == "ldaps":
                use_ssl = True
            elif security == "ldap":
                use_ssl = False
            else:
                raise ValueError

            return (
                use_ssl,
                url,
                port,
                ldap_user,
                ldap_pass,
                dn_subtree,
                search_filter_key,
            )
        except ValueError:
            raise exceptions.OptionsError(f"Invalid LDAP specification: {spec}")

    def make_search_filter(self, username: str) -> str:
        """
        为 LDAP 认证构造搜索过滤表达式。
        """
        username = ldap3.utils.conv.escape_filter_chars(username)
        return f"({self.filter_key}={username})"

    def __call__(self, username: str, password: str) -> bool:
        """
        让对象可以像函数一样被调用。
        """
        if not username or not password:
            return False
        self.conn.search(self.dn_subtree, self.make_search_filter(username))
        if self.conn.response:
            c = ldap3.Connection(
                self.server, self.conn.response[0]["dn"], password, auto_bind=True
            )
            if c:
                return True
        return False
