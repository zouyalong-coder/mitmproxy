"""
检测 Server-Sent Events 响应并提示当前限制的内置 addon。

触发点：
- `response`：HTTP 响应体读取完成、返回客户端前触发；如果是 SSE 且未开启流式响应则警告。
"""

import logging

from mitmproxy import http


class ServerSideEvents:
    """
    Server-Side Events are currently swallowed if there's no streaming,
    see https://github.com/mitmproxy/mitmproxy/issues/4469.

    Until this bug is fixed, this addon warns the user about this.
    
    中文说明：当前非流式 SSE 会被完整缓冲，破坏事件流语义。本 addon 不修改
    flow，只在检测到风险时提醒用户开启 response streaming。
    """

    def response(self, flow: http.HTTPFlow):
        """
        HTTP `response` 事件：响应体读取完成、返回客户端前触发。

        检查 `Content-Type: text/event-stream`，并在响应未流式处理时记录警告。
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
