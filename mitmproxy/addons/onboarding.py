"""
托管 mitm.it 证书安装引导页的内置 addon。

触发点：
- `load`：addon 加载时注册 `onboarding` 和 `onboarding_host`。
- `configure`：选项变化时更新托管域名和配置目录。
- `request`：HTTP 请求发往上游前触发；如果目标 host 匹配引导站点则由本地 WSGI app 响应。
"""

from mitmproxy import ctx
from mitmproxy.addons import asgiapp
from mitmproxy.addons.onboardingapp import app

APP_HOST = "mitm.it"


class Onboarding(asgiapp.WSGIApp):
    """
    将 `mitmproxy.addons.onboardingapp` 作为 WSGI 应用挂到 mitmproxy 内部。
    """
    name = "onboarding"

    def __init__(self):
        """
        初始化引导页应用，默认绑定到 `mitm.it` 的任意端口。
        """
        super().__init__(app, APP_HOST, None)

    def load(self, loader):
        """
        addon 加载事件：注册引导页开关和主机名。
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
        `configure` 事件：选项变化后触发。

        `onboarding_host` 决定 request hook 的 host 匹配；`CONFDIR` 提供证书
        文件读取位置。
        """
        self.host = ctx.options.onboarding_host
        app.config["CONFDIR"] = ctx.options.confdir

    async def request(self, f):
        """
        HTTP `request` 事件：请求发往上游前触发。

        开启 `onboarding` 后交给父类 WSGIApp 判断 host 并生成本地响应。
        """
        if ctx.options.onboarding:
            await super().request(f)
