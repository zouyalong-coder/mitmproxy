"""
`mitmproxy.addons.upstream_auth` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import base64
import re
from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy.proxy import mode_specs
from mitmproxy.utils import strutils


def parse_upstream_auth(auth: str) -> bytes:
    """
    解析上游代理认证配置，生成用户名和密码。
    """
    pattern = re.compile(".+:")
    if pattern.search(auth) is None:
        raise exceptions.OptionsError("Invalid upstream auth specification: %s" % auth)
    return b"Basic" + b" " + base64.b64encode(strutils.always_bytes(auth))


class UpstreamAuth:
    """
    This addon handles authentication to systems upstream from us for the
    upstream proxy and reverse proxy mode. There are 3 cases:

    - Upstream proxy CONNECT requests should have authentication added, and
      subsequent already connected requests should not.
    - Upstream proxy regular requests
    - Reverse proxy regular requests (CONNECT is invalid in this mode)
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    auth: bytes | None = None

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "upstream_auth",
            Optional[str],
            None,
            """
            Add HTTP Basic authentication to upstream proxy and reverse proxy
            requests. Format: username:password.
            """,
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "upstream_auth" in updated:
            if ctx.options.upstream_auth is None:
                self.auth = None
            else:
                self.auth = parse_upstream_auth(ctx.options.upstream_auth)

    def http_connect_upstream(self, f: http.HTTPFlow):
        """
        处理即将发往上游代理的 HTTP CONNECT 请求。
        """
        if self.auth:
            f.request.headers["Proxy-Authorization"] = self.auth

    def requestheaders(self, f: http.HTTPFlow):
        """
        处理 HTTP 请求头事件，适合在 body 读取前决定流式处理或改写头部。
        """
        if self.auth:
            if (
                isinstance(f.client_conn.proxy_mode, mode_specs.UpstreamMode)
                and f.request.scheme == "http"
            ):
                f.request.headers["Proxy-Authorization"] = self.auth
            elif isinstance(f.client_conn.proxy_mode, mode_specs.ReverseMode):
                f.request.headers["Authorization"] = self.auth
