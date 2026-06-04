"""
按规则增删 HTTP 请求头或响应头的内置 addon。

触发点：
- `load`：addon 加载时注册 `modify_headers`。
- `configure`：`modify_headers` 变化时解析并校验规则。
- `requestheaders`：请求头解析完成、请求体读取前触发。
- `responseheaders`：响应头解析完成、响应体读取前触发。
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
    表示一条头部或 body 修改规则。

    `matches` 是 flow filter，`subject` 是待修改的头名或 body 正则，
    `replacement_str` 是替换值；以 `@` 开头时表示从文件读取替换内容。
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
        
        中文说明：把配置中的替换值转换为 bytes。如果替换值以 `@` 开头，
        则把后续内容当作文件路径并读取文件内容。
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
    维护头部修改规则，并在请求头/响应头阶段应用。
    """

    def __init__(self) -> None:
        """
        初始化已解析的头部替换规则列表。
        """
        self.replacements: list[ModifySpec] = []

    def load(self, loader):
        """
        addon 加载事件：注册 `modify_headers` 配置项。
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
        `configure` 事件：选项变化后触发。

        规则在这里预解析；如果 `@file` 路径不可读，会拒绝本次配置更新。
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
        HTTP `requestheaders` 事件：请求头解析完成、请求体读取前触发。
        """
        if flow.response or flow.error or not flow.live:
            return
        self.run(flow, flow.request.headers)

    def responseheaders(self, flow):
        """
        HTTP `responseheaders` 事件：响应头解析完成、响应体读取前触发。
        """
        if flow.error or not flow.live:
            return
        self.run(flow, flow.response.headers)

    def run(self, flow: http.HTTPFlow, hdrs: Headers) -> None:
        """
        对传入的头集合应用所有命中的修改规则。

        先基于“未修改前的 flow”计算哪些规则命中，再删除目标头，最后按规则
        添加新值。这样可以避免前一条规则的修改影响后一条规则的匹配结果。
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
