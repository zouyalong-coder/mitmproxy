"""
在反向代理模式下改写 Alt-Svc 响应头的内置 addon。

触发点：
- `load`：addon 加载时注册 `keep_alt_svc_header`。
- `responseheaders`：HTTP 响应头解析完成、响应体读取前触发。
"""

import re

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow
from mitmproxy.proxy import mode_specs

ALT_SVC = "alt-svc"
HOST_PATTERN = r"([a-zA-Z0-9.-]*:\d{1,5})"


def update_alt_svc_header(header: str, port: int) -> str:
    """
    改写 Alt-Svc 头中的 host:port，使替代服务仍指向 mitmproxy 监听端口。
    """
    return re.sub(HOST_PATTERN, f":{port}", header)


class UpdateAltSvc:
    """
    防止反向代理响应中的 Alt-Svc 让客户端绕过 mitmproxy 直连真实服务。
    """

    def load(self, loader):
        """
        addon 加载事件：注册是否保留原始 Alt-Svc 的开关。
        """
        loader.add_option(
            "keep_alt_svc_header",
            bool,
            False,
            "Reverse Proxy: Keep Alt-Svc headers as-is, even if they do not point to mitmproxy. Enabling this option may cause clients to bypass the proxy.",
        )

    def responseheaders(self, flow: HTTPFlow):
        """
        HTTP `responseheaders` 事件：响应头解析完成、响应体读取前触发。

        只在 ReverseMode 中处理；默认把 Alt-Svc 里的端口改成当前 mitmproxy
        监听端口，让客户端继续通过代理访问替代服务。
        """
        assert flow.response
        if (
            not ctx.options.keep_alt_svc_header
            and isinstance(flow.client_conn.proxy_mode, mode_specs.ReverseMode)
            and ALT_SVC in flow.response.headers
        ):
            _, listen_port, *_ = flow.client_conn.sockname
            headers = flow.response.headers
            headers[ALT_SVC] = update_alt_svc_header(headers[ALT_SVC], listen_port)
