"""
去除客户端缓存验证头的内置 addon。

触发点：
- `load`：addon 加载时注册 `anticache` 选项。
- `request`：每个 HTTP 请求进入代理处理链时触发，按需删除会导致 304 的请求头。
"""

from mitmproxy import ctx


class AntiCache:
    """
    负责让上游服务器尽量返回完整响应，而不是 304 Not Modified。
    """

    def load(self, loader):
        """
        addon 加载事件：注册 `anticache` 开关。
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
        HTTP `request` 事件：请求头已解析完成、发往上游前触发。

        开启后调用 `flow.request.anticache()` 删除 If-None-Match、
        If-Modified-Since 等缓存验证头。
        """
        if ctx.options.anticache:
            flow.request.anticache()
