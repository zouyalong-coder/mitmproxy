"""
`mitmproxy.addons.stickycookie` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    
    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
    `stickycookie` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.jar: collections.defaultdict[TOrigin, dict[str, str]] = (
            collections.defaultdict(dict)
        )
        self.flt: flowfilter.TFilter | None = None

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "stickycookie",
            Optional[str],
            None,
            "Set sticky cookie filter. Matched against requests.",
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        处理 HTTP 响应生命周期事件，可读取或修改 response flow。
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
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
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
