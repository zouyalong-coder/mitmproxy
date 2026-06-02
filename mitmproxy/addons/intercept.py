"""
`mitmproxy.addons.intercept` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import flowfilter


class Intercept:
    """
    `intercept` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    filt: flowfilter.TFilter | None = None

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option("intercept_active", bool, False, "Intercept toggle")
        loader.add_option(
            "intercept", Optional[str], None, "Intercept filter expression."
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "intercept" in updated:
            if ctx.options.intercept:
                try:
                    self.filt = flowfilter.parse(ctx.options.intercept)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
                ctx.options.intercept_active = True
            else:
                self.filt = None
                ctx.options.intercept_active = False

    def should_intercept(self, f: flow.Flow) -> bool:
        """
        根据当前配置和 flow 状态判断是否应执行后续处理。
        """
        return bool(
            ctx.options.intercept_active
            and self.filt
            and self.filt(f)
            and not f.is_replay
        )

    def process_flow(self, f: flow.Flow) -> None:
        """
        `intercept` addon 中的方法，用于处理 `process flow` 相关逻辑。
        """
        if self.should_intercept(f):
            f.intercept()

    # Handlers

    def request(self, f):
        """
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        self.process_flow(f)

    def response(self, f):
        """
        处理 HTTP 响应生命周期事件，可读取或修改 response flow。
        """
        self.process_flow(f)

    def tcp_message(self, f):
        """
        处理 TCP 消息事件。
        """
        self.process_flow(f)

    def udp_message(self, f):
        """
        处理 UDP 消息事件。
        """
        self.process_flow(f)

    def dns_request(self, f):
        """
        处理 DNS 请求事件。
        """
        self.process_flow(f)

    def dns_response(self, f):
        """
        处理 DNS 响应事件。
        """
        self.process_flow(f)

    def websocket_message(self, f):
        """
        处理 WebSocket 消息事件。
        """
        self.process_flow(f)
