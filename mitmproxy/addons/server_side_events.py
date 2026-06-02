"""
`mitmproxy.addons.server_side_events` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import logging

from mitmproxy import http


class ServerSideEvents:
    """
    Server-Side Events are currently swallowed if there's no streaming,
    see https://github.com/mitmproxy/mitmproxy/issues/4469.

    Until this bug is fixed, this addon warns the user about this.
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    def response(self, flow: http.HTTPFlow):
        """
        处理 HTTP 响应生命周期事件，可读取或修改 response flow。
        """
        assert flow.response
        is_sse = flow.response.headers.get("content-type", "").startswith(
            "text/event-stream"
        )
        if is_sse and not flow.response.stream:
            logging.warning(
                "mitmproxy currently does not support server side events. As a workaround, you can enable response "
                "streaming for such flows: https://github.com/mitmproxy/mitmproxy/issues/4469"
            )
