"""
按过滤条件保存并复用 Cookie 的内置 addon。

触发点：
- `load`：addon 加载时注册 `stickycookie` 选项。
- `configure`：过滤表达式变化时重新解析。
- `response`：HTTP 响应返回时收集 Set-Cookie。
- `request`：HTTP 请求发往上游前，把已保存且匹配域名/端口/路径的 Cookie 写回请求。
"""

import collections
from http import cookiejar
from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.net.http import cookies

TOrigin = tuple[str, int, str]


def ckey(attrs: dict[str, str], f: http.HTTPFlow) -> TOrigin:
    """
    Returns a (domain, port, path) tuple.
    
    中文说明：根据响应中的 Cookie 属性和当前请求，计算 cookie jar 的键。
    Domain/Path 属性会覆盖默认的请求 host 和根路径。
    """
    domain = f.request.host
    path = "/"
    if "domain" in attrs:
        domain = attrs["domain"]
    if "path" in attrs:
        path = attrs["path"]
    return (domain, f.request.port, path)


def domain_match(a: str, b: str) -> bool:
    """
    判断 cookie 域名规则是否匹配当前请求域名。
    """
    if cookiejar.domain_match(a, b):  # type: ignore
        return True
    elif cookiejar.domain_match(a, b.strip(".")):  # type: ignore
        return True
    return False


class StickyCookie:
    """
    在响应阶段记录 Cookie，并在后续匹配请求中自动附加。
    """

    def __init__(self) -> None:
        """
        初始化 cookie jar 和可选的 flow filter。
        """
        self.jar: collections.defaultdict[TOrigin, dict[str, str]] = (
            collections.defaultdict(dict)
        )
        self.flt: flowfilter.TFilter | None = None

    def load(self, loader):
        """
        addon 加载事件：注册 `stickycookie` 过滤表达式。
        """
        loader.add_option(
            "stickycookie",
            Optional[str],
            None,
            "Set sticky cookie filter. Matched against requests.",
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        `stickycookie` 是 flow filter 字符串，解析失败会拒绝本次配置更新。
        """
        if "stickycookie" in updated:
            if ctx.options.stickycookie:
                try:
                    self.flt = flowfilter.parse(ctx.options.stickycookie)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            else:
                self.flt = None

    def response(self, flow: http.HTTPFlow):
        """
        HTTP `response` 事件：响应体读取完成、返回客户端前触发。

        这里读取响应 Cookie：未过期则写入 jar，已过期则从 jar 中移除。
        """
        assert flow.response
        if self.flt:
            for name, (value, attrs) in flow.response.cookies.items(multi=True):
                # FIXME: We now know that Cookie.py screws up some cookies with
                # valid RFC 822/1123 datetime specifications for expiry. Sigh.
                dom_port_path = ckey(attrs, flow)

                if domain_match(flow.request.host, dom_port_path[0]):
                    if cookies.is_expired(attrs):
                        # Remove the cookie from jar
                        self.jar[dom_port_path].pop(name, None)

                        # If all cookies of a dom_port_path have been removed
                        # then remove it from the jar itself
                        if not self.jar[dom_port_path]:
                            self.jar.pop(dom_port_path, None)
                    else:
                        self.jar[dom_port_path][name] = value

    def request(self, flow: http.HTTPFlow):
        """
        HTTP `request` 事件：请求体读取完成、发往上游前触发。

        当请求匹配过滤器时，从 jar 中挑选 domain/port/path 都适用的 Cookie，
        并写入请求头。
        """
        if self.flt:
            cookie_list: list[tuple[str, str]] = []
            if flowfilter.match(self.flt, flow):
                for (domain, port, path), c in self.jar.items():
                    match = [
                        domain_match(flow.request.host, domain),
                        flow.request.port == port,
                        flow.request.path.startswith(path),
                    ]
                    if all(match):
                        cookie_list.extend(c.items())
            if cookie_list:
                # FIXME: we need to formalise this...
                flow.metadata["stickycookie"] = True
                flow.request.headers["cookie"] = cookies.format_cookie_header(
                    cookie_list
                )
