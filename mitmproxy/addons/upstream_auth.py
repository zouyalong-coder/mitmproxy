"""
为上游代理或反向代理目标添加 HTTP Basic 认证的内置 addon。

触发点：
- `load`：addon 加载时注册 `upstream_auth`。
- `configure`：认证配置变化时生成 Basic 认证头。
- `http_connect_upstream`：CONNECT 请求即将发往上游代理时触发。
- `requestheaders`：普通 HTTP 请求头发往上游前触发。
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
    解析 `username:password` 配置并生成 Basic 认证头字节串。
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
    
    中文说明：这个 addon 处理的是“mitmproxy 到上游”的认证，不是客户端到
    mitmproxy 的代理认证。上游代理模式使用 `Proxy-Authorization`，反向代理
    模式使用普通 `Authorization`。
    """

    auth: bytes | None = None

    def load(self, loader):
        """
        addon 加载事件：注册 `upstream_auth` 配置项。
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
        `configure` 事件：选项变化后触发。

        认证字符串会在这里预先编码成 header 值，避免每个请求重复处理。
        """
        if "upstream_auth" in updated:
            if ctx.options.upstream_auth is None:
                self.auth = None
            else:
                self.auth = parse_upstream_auth(ctx.options.upstream_auth)

    def http_connect_upstream(self, f: http.HTTPFlow):
        """
        `http_connect_upstream` 事件：CONNECT 请求发送给上游代理前触发。

        HTTPS 经上游代理建立隧道时，认证必须放在这条 CONNECT 请求上。
        """
        if self.auth:
            f.request.headers["Proxy-Authorization"] = self.auth

    def requestheaders(self, f: http.HTTPFlow):
        """
        HTTP `requestheaders` 事件：普通请求头发往上游前触发。

        上游代理处理明文 HTTP 请求时写 `Proxy-Authorization`；反向代理模式
        直接向目标服务写 `Authorization`。
        """
        if self.auth:
            if (
                isinstance(f.client_conn.proxy_mode, mode_specs.UpstreamMode)
                and f.request.scheme == "http"
            ):
                f.request.headers["Proxy-Authorization"] = self.auth
            elif isinstance(f.client_conn.proxy_mode, mode_specs.ReverseMode):
                f.request.headers["Authorization"] = self.auth
