"""
按规则把请求 URL 重写到另一个远程 URL 的内置 addon。

触发点：
- `load`：addon 加载时注册 `map_remote` 选项。
- `configure`：`map_remote` 变化时解析并缓存重写规则。
- `request`：每个 HTTP 请求发往上游前触发，命中规则时重写 `flow.request.url`。
"""

import re
from collections.abc import Sequence
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.utils.spec import parse_spec


class MapRemoteSpec(NamedTuple):
    """
    表示 map-remote 的单条规则。

    `matches` 先用 flow filter 判断是否适用，`subject` 是匹配原 URL 的正则，
    `replacement` 是替换后的远程 URL 模板。
    """
    matches: flowfilter.TFilter
    subject: str
    replacement: str


def parse_map_remote_spec(option: str) -> MapRemoteSpec:
    """
    解析 map-remote 配置字符串，生成匹配规则和远程替换地址。
    """
    spec = MapRemoteSpec(*parse_spec(option))

    try:
        re.compile(spec.subject)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {spec.subject!r} ({e})")

    return spec


class MapRemote:
    """
    维护 URL 重写规则，并在 HTTP 请求进入上游前应用。
    """

    def __init__(self) -> None:
        """
        初始化已解析的重写规则列表。
        """
        self.replacements: list[MapRemoteSpec] = []

    def load(self, loader):
        """
        addon 加载事件：注册 `map_remote` 配置项。
        """
        loader.add_option(
            "map_remote",
            Sequence[str],
            [],
            """
            Map remote resources to another remote URL using a pattern of the form
            "[/flow-filter]/url-regex/replacement", where the separator can
            be any character.
            """,
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        当 `map_remote` 更新时重新解析规则，正则非法时抛出 OptionsError 让
        配置系统回滚本次更新。
        """
        if "map_remote" in updated:
            self.replacements = []
            for option in ctx.options.map_remote:
                try:
                    spec = parse_map_remote_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_remote option {option}: {e}"
                    ) from e

                self.replacements.append(spec)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        HTTP `request` 事件：请求发往上游前触发。

        如果 URL 被重写，设置 `flow.request.url` 会同步更新 Host 头，这是
        map-remote 改写目标服务器的关键机制。
        """
        if flow.response or flow.error or not flow.live:
            return
        for spec in self.replacements:
            if spec.matches(flow):
                url = flow.request.pretty_url
                new_url = re.sub(spec.subject, spec.replacement, url)
                # this is a bit messy: setting .url also updates the host header,
                # so we really only do that if the replacement affected the URL.
                if url != new_url:
                    flow.request.url = new_url  # type: ignore
