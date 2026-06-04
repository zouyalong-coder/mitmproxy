"""
按主机记住并复用 Authorization 头的内置 addon。

触发点：
- `load`：addon 加载时注册 `stickyauth` 选项。
- `configure`：过滤表达式变化时重新解析。
- `request`：每个 HTTP 请求发往上游前触发，记录或补充 Authorization 头。
"""

from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter


class StickyAuth:
    """
    在用户首次认证后记住某个 host 的 Authorization 头，并复用到后续请求。
    """

    def __init__(self):
        """
        初始化过滤器和 host 到 Authorization 值的缓存。
        """
        self.flt = None
        self.hosts = {}

    def load(self, loader):
        """
        addon 加载事件：注册 `stickyauth` 过滤表达式。
        """
        loader.add_option(
            "stickyauth",
            Optional[str],
            None,
            "Set sticky auth filter. Matched against requests.",
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        `stickyauth` 是 flow filter 字符串，解析失败会拒绝本次配置更新。
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
        HTTP `request` 事件：请求发往上游前触发。

        如果当前请求自带 Authorization，则按 host 记住；如果没有但请求匹配
        过滤器，则尝试复用同 host 的历史认证头。
        """
        if self.flt:
            host = flow.request.host
            if "authorization" in flow.request.headers:
                self.hosts[host] = flow.request.headers["authorization"]
            elif flowfilter.match(self.flt, flow):
                if host in self.hosts:
                    flow.request.headers["authorization"] = self.hosts[host]
