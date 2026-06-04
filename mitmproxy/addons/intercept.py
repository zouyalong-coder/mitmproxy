"""
按 flow filter 自动拦截流量的内置 addon。

触发点：
- `load`：注册拦截开关和过滤表达式。
- `configure`：过滤表达式变化时重新解析，并同步 `intercept_active`。
- HTTP：`request`、`response`。
- TCP/UDP：`tcp_message`、`udp_message`。
- DNS：`dns_request`、`dns_response`。
- WebSocket：`websocket_message`。
"""

from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import flowfilter


class Intercept:
    """
    在多个协议事件点检查 flow filter，命中时调用 `flow.intercept()` 暂停流。
    """
    filt: flowfilter.TFilter | None = None

    def load(self, loader):
        """
        addon 加载事件：注册拦截相关选项。
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
        对任意协议 flow 执行统一拦截判断。
        """
        if self.should_intercept(f):
            f.intercept()

    # Handlers

    def request(self, f):
        """
        HTTP `request` 事件：请求发往上游前触发。
        """
        self.process_flow(f)

    def response(self, f):
        """
        HTTP `response` 事件：响应返回客户端前触发。
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
