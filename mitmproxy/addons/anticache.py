"""
`mitmproxy.addons.anticache` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from mitmproxy import ctx


class AntiCache:
    """
    `anticache` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "anticache",
            bool,
            False,
            """
            Strip out request headers that might cause the server to return
            304-not-modified.
            """,
        )

    def request(self, flow):
        """
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        if ctx.options.anticache:
            flow.request.anticache()
