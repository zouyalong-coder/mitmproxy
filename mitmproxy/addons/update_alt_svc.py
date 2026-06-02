"""
`mitmproxy.addons.update_alt_svc` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import re

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow
from mitmproxy.proxy import mode_specs

ALT_SVC = "alt-svc"
HOST_PATTERN = r"([a-zA-Z0-9.-]*:\d{1,5})"


def update_alt_svc_header(header: str, port: int) -> str:
    """
    改写 Alt-Svc 头，避免客户端绕过 mitmproxy 直接使用 HTTP/3 等替代服务。
    """
    return re.sub(HOST_PATTERN, f":{port}", header)


class UpdateAltSvc:
    """
    `update_alt_svc` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "keep_alt_svc_header",
            bool,
            False,
            "Reverse Proxy: Keep Alt-Svc headers as-is, even if they do not point to mitmproxy. Enabling this option may cause clients to bypass the proxy.",
        )

    def responseheaders(self, flow: HTTPFlow):
        """
        处理 HTTP 响应头事件，适合在 body 读取前决定流式处理或改写头部。
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
