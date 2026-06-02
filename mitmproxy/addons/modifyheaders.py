"""
`mitmproxy.addons.modifyheaders` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import logging
import re
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.http import Headers
from mitmproxy.utils import strutils
from mitmproxy.utils.spec import parse_spec


class ModifySpec(NamedTuple):
    """
    表示请求/响应修改规则的解析结果。
    """
    matches: flowfilter.TFilter
    subject: bytes
    replacement_str: str

    def read_replacement(self) -> bytes:
        """
        Process the replacement str. This usually just involves converting it to bytes.
        However, if it starts with `@`, we interpret the rest as a file path to read from.

        Raises:
            - IOError if the file cannot be read.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        if self.replacement_str.startswith("@"):
            return Path(self.replacement_str[1:]).expanduser().read_bytes()
        else:
            # We could cache this at some point, but unlikely to be a problem.
            return strutils.escaped_str_to_bytes(self.replacement_str)


def parse_modify_spec(option: str, subject_is_regex: bool) -> ModifySpec:
    """
    解析修改规则配置，拆分过滤表达式、匹配模式和替换内容。
    """
    flow_filter, subject_str, replacement = parse_spec(option)

    subject = strutils.escaped_str_to_bytes(subject_str)
    if subject_is_regex:
        try:
            re.compile(subject)
        except re.error as e:
            raise ValueError(f"Invalid regular expression {subject!r} ({e})")

    spec = ModifySpec(flow_filter, subject, replacement)

    try:
        spec.read_replacement()
    except OSError as e:
        raise ValueError(f"Invalid file path: {replacement[1:]} ({e})")

    return spec


class ModifyHeaders:
    """
    `modifyheaders` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
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
            "modify_headers",
            Sequence[str],
            [],
            """
            Header modify pattern of the form "[/flow-filter]/header-name/[@]header-value", where the
            separator can be any character. The @ allows to provide a file path that is used to read
            the header value string. An empty header-value removes existing header-name headers.
            """,
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "modify_headers" in updated:
            self.replacements = []
            for option in ctx.options.modify_headers:
                try:
                    spec = parse_modify_spec(option, False)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse modify_headers option {option}: {e}"
                    ) from e
                self.replacements.append(spec)

    def requestheaders(self, flow):
        """
        处理 HTTP 请求头事件，适合在 body 读取前决定流式处理或改写头部。
        """
        if flow.response or flow.error or not flow.live:
            return
        self.run(flow, flow.request.headers)

    def responseheaders(self, flow):
        """
        处理 HTTP 响应头事件，适合在 body 读取前决定流式处理或改写头部。
        """
        if flow.error or not flow.live:
            return
        self.run(flow, flow.response.headers)

    def run(self, flow: http.HTTPFlow, hdrs: Headers) -> None:
        """
        `modifyheaders` addon 中的方法，用于处理 `run` 相关逻辑。
        """
        matches = []

        # first check all the filters against the original, unmodified flow
        for spec in self.replacements:
            matches.append(spec.matches(flow))

        # unset all specified headers
        for i, spec in enumerate(self.replacements):
            if matches[i]:
                hdrs.pop(spec.subject, None)

        # set all specified headers if the replacement string is not empty

        for i, spec in enumerate(self.replacements):
            if matches[i]:
                try:
                    replacement = spec.read_replacement()
                except OSError as e:
                    logging.warning(f"Could not read replacement file: {e}")
                    continue
                else:
                    if replacement:
                        hdrs.add(spec.subject, replacement)
