"""
`mitmproxy.addons.stickyauth` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter


class StickyAuth:
    """
    `stickyauth` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self):
        """
        初始化对象状态。
        """
        self.flt = None
        self.hosts = {}

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "stickyauth",
            Optional[str],
            None,
            "Set sticky auth filter. Matched against requests.",
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "stickyauth" in updated:
            if ctx.options.stickyauth:
                try:
                    self.flt = flowfilter.parse(ctx.options.stickyauth)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            else:
                self.flt = None

    def request(self, flow):
        """
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        if self.flt:
            host = flow.request.host
            if "authorization" in flow.request.headers:
                self.hosts[host] = flow.request.headers["authorization"]
            elif flowfilter.match(self.flt, flow):
                if host in self.hosts:
                    flow.request.headers["authorization"] = self.hosts[host]
