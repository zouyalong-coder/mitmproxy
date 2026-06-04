"""
按正则替换 HTTP 请求体或响应体的内置 addon。

触发点：
- `load`：addon 加载时注册 `modify_body`。
- `configure`：`modify_body` 或 `stream_large_bodies` 变化时解析规则/提示冲突。
- `request`：HTTP 请求体完整可用且发往上游前触发。
- `response`：HTTP 响应体完整可用且返回客户端前触发。
"""

import logging
import re
from collections.abc import Sequence

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy.addons.modifyheaders import ModifySpec
from mitmproxy.addons.modifyheaders import parse_modify_spec
from mitmproxy.log import ALERT

logger = logging.getLogger(__name__)


class ModifyBody:
    """
    维护 body 替换规则，并在请求/响应阶段对内容做正则替换。
    """

    def __init__(self) -> None:
        """
        初始化已解析的替换规则列表。
        """
        self.replacements: list[ModifySpec] = []

    def load(self, loader):
        """
        addon 加载事件：注册 `modify_body` 配置项。
        """
        loader.add_option(
            "modify_body",
            Sequence[str],
            [],
            """
            Replacement pattern of the form "[/flow-filter]/regex/[@]replacement", where
            the separator can be any character. The @ allows to provide a file path that
            is used to read the replacement string.
            """,
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        规则会在这里预解析，替换内容以 `@` 开头时会预检查文件是否可读；
        同时提醒用户流式大 body 不会被此 addon 修改。
        """
        if "modify_body" in updated:
            self.replacements = []
            for option in ctx.options.modify_body:
                try:
                    spec = parse_modify_spec(option, True)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse modify_body option {option}: {e}"
                    ) from e

                self.replacements.append(spec)

        stream_and_modify_conflict = (
            ctx.options.modify_body
            and ctx.options.stream_large_bodies
            and ("modify_body" in updated or "stream_large_bodies" in updated)
        )
        if stream_and_modify_conflict:
            logger.log(
                ALERT,
                "Both modify_body and stream_large_bodies are active. "
                "Streamed bodies will not be modified.",
            )

    def request(self, flow):
        """
        HTTP `request` 事件：请求体已读取、发往上游前触发。
        """
        if flow.response or flow.error or not flow.live:
            return
        self.run(flow)

    def response(self, flow):
        """
        HTTP `response` 事件：响应体已读取、返回客户端前触发。
        """
        if flow.error or not flow.live:
            return
        self.run(flow)

    def run(self, flow):
        """
        对当前 flow 的请求体或响应体应用替换规则。

        如果 `flow.response` 已存在则修改响应体，否则修改请求体。替换值可以是
        配置里的字面量，也可以来自 `@file` 指定的文件内容。
        """
        for spec in self.replacements:
            if spec.matches(flow):
                try:
                    replacement = spec.read_replacement()
                except OSError as e:
                    logging.warning(f"Could not read replacement file: {e}")
                    continue
                if flow.response:
                    flow.response.content = re.sub(
                        spec.subject,
                        lambda _: replacement,
                        flow.response.content,
                        flags=re.DOTALL,
                    )
                else:
                    flow.request.content = re.sub(
                        spec.subject,
                        lambda _: replacement,
                        flow.request.content,
                        flags=re.DOTALL,
                    )
