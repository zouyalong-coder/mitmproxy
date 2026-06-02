"""
`mitmproxy.addons.mapremote` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    表示 map-remote 的匹配规则和远程替换目标。
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
    `mapremote` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.replacements: list[MapRemoteSpec] = []

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
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
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
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
