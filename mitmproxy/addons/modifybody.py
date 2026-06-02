"""
`mitmproxy.addons.modifybody` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    `modifybody` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.replacements: list[ModifySpec] = []

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
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
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        if flow.response or flow.error or not flow.live:
            return
        self.run(flow)

    def response(self, flow):
        """
        处理 HTTP 响应生命周期事件，可读取或修改 response flow。
        """
        if flow.error or not flow.live:
            return
        self.run(flow)

    def run(self, flow):
        """
        `modifybody` addon 中的方法，用于处理 `run` 相关逻辑。
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
