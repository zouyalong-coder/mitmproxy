"""
`mitmproxy.addons.onboarding` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from mitmproxy import ctx
from mitmproxy.addons import asgiapp
from mitmproxy.addons.onboardingapp import app

APP_HOST = "mitm.it"


class Onboarding(asgiapp.WSGIApp):
    """
    `onboarding` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    name = "onboarding"

    def __init__(self):
        """
        初始化对象状态。
        """
        super().__init__(app, APP_HOST, None)

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "onboarding", bool, True, "Toggle the mitmproxy onboarding app."
        )
        loader.add_option(
            "onboarding_host",
            str,
            APP_HOST,
            """
            Onboarding app domain. For transparent mode, use an IP when a DNS
            entry for the app domain is not present.
            """,
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        self.host = ctx.options.onboarding_host
        app.config["CONFDIR"] = ctx.options.confdir

    async def request(self, f):
        """
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        if ctx.options.onboarding:
            await super().request(f)
