"""
尝试让上游服务器返回未压缩响应体的内置 addon。

触发点：
- `load`：addon 加载时注册 `anticomp` 选项。
- `request`：每个 HTTP 请求发往上游前触发，按需调整 Accept-Encoding。
"""

from mitmproxy import ctx


class AntiComp:
    """
    通过修改请求头降低响应体被 gzip/br 等压缩的概率，方便查看和替换内容。
    """

    def load(self, loader):
        """
        addon 加载事件：注册 `anticomp` 开关。
        """
        loader.add_option(
            "anticomp",
            bool,
            False,
            "Try to convince servers to send us un-compressed data.",
        )

    def request(self, flow):
        """
        HTTP `request` 事件：请求头已解析完成、发往上游前触发。

        开启后调用 `flow.request.anticomp()` 调整压缩相关请求头。
        """
        if ctx.options.anticomp:
            flow.request.anticomp()
