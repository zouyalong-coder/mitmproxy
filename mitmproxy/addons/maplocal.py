"""
按规则用本地文件响应远程请求的内置 addon。

触发点：
- `load`：addon 加载时注册 `map_local` 选项。
- `configure`：`map_local` 变化时解析规则并校验本地路径。
- `request`：每个 HTTP 请求发往上游前触发，命中本地文件时直接生成响应。
"""

import logging
import mimetypes
import re
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from werkzeug.security import safe_join

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import version
from mitmproxy.utils.spec import parse_spec


class MapLocalSpec(NamedTuple):
    """
    表示 map-local 的单条规则。

    `matches` 判断 flow 是否适用，`regex` 从 URL 中截取路径后缀，
    `local_path` 指向本地文件或目录。
    """
    matches: flowfilter.TFilter
    regex: str
    local_path: Path


def parse_map_local_spec(option: str) -> MapLocalSpec:
    """
    解析 map-local 配置字符串，生成匹配规则和本地路径。
    """
    filter, regex, replacement = parse_spec(option)

    try:
        re.compile(regex)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {regex!r} ({e})")

    try:
        path = Path(replacement).expanduser().resolve(strict=True)
    except FileNotFoundError as e:
        raise ValueError(f"Invalid file path: {replacement} ({e})")

    return MapLocalSpec(filter, regex, path)


def _safe_path_join(root: Path, untrusted: str) -> Path:
    """
    Join a Path element with an untrusted str.

    This is a convenience wrapper for werkzeug's safe_join,
    raising a ValueError if the path is malformed.

    中文说明：把 URL 派生出的不可信路径拼到本地根目录下，并防止 `../`
    逃逸到映射目录之外。
    """
    untrusted_parts = Path(untrusted).parts
    joined = safe_join(root.as_posix(), *untrusted_parts)
    if joined is None:
        raise ValueError("Untrusted paths.")
    return Path(joined)


def file_candidates(url: str, spec: MapLocalSpec) -> list[Path]:
    """
    Get all potential file candidates given a URL and a mapping spec ordered by preference.
    This function already assumes that the spec regex matches the URL.
    
    中文说明：根据 URL 和规则生成候选文件列表。目录映射会优先尝试解码后的
    路径和 `index.html`，必要时再尝试转义后的安全文件名。
    """
    m = re.search(spec.regex, url)
    assert m
    if m.groups():
        suffix = m.group(1)
    else:
        suffix = re.split(spec.regex, url, maxsplit=1)[1]
        suffix = suffix.split("?")[0]  # remove query string
        suffix = suffix.strip("/")

    if suffix:
        decoded_suffix = urllib.parse.unquote(suffix)
        suffix_candidates = [decoded_suffix, f"{decoded_suffix}/index.html"]

        escaped_suffix = re.sub(r"[^0-9a-zA-Z\-_.=(),/]", "_", decoded_suffix)
        if decoded_suffix != escaped_suffix:
            suffix_candidates.extend([escaped_suffix, f"{escaped_suffix}/index.html"])
        try:
            return [_safe_path_join(spec.local_path, x) for x in suffix_candidates]
        except ValueError:
            return []
    else:
        return [spec.local_path / "index.html"]


class MapLocal:
    """
    维护本地映射规则，并在请求阶段用文件内容短路上游访问。
    """

    def __init__(self) -> None:
        """
        初始化已解析的本地映射规则列表。
        """
        self.replacements: list[MapLocalSpec] = []

    def load(self, loader):
        """
        addon 加载事件：注册 `map_local` 配置项。
        """
        loader.add_option(
            "map_local",
            Sequence[str],
            [],
            """
            Map remote resources to a local file using a pattern of the form
            "[/flow-filter]/url-regex/file-or-directory-path", where the
            separator can be any character.
            """,
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        当 `map_local` 更新时重新解析规则，并在配置阶段确认本地路径存在。
        """
        if "map_local" in updated:
            self.replacements = []
            for option in ctx.options.map_local:
                try:
                    spec = parse_map_local_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_local option {option}: {e}"
                    ) from e

                self.replacements.append(spec)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        HTTP `request` 事件：请求发往上游前触发。

        命中本地文件后直接设置 `flow.response`，后续代理层不会再把请求发送到
        远程服务器；若规则命中但候选文件都不存在，则返回 404。
        """
        if flow.response or flow.error or not flow.live:
            return

        url = flow.request.pretty_url

        all_candidates = []
        for spec in self.replacements:
            if spec.matches(flow) and re.search(spec.regex, url):
                if spec.local_path.is_file():
                    candidates = [spec.local_path]
                else:
                    candidates = file_candidates(url, spec)
                all_candidates.extend(candidates)

                local_file = None
                for candidate in candidates:
                    if candidate.is_file():
                        local_file = candidate
                        break

                if local_file:
                    headers = {"Server": version.MITMPROXY}
                    mimetype = mimetypes.guess_type(str(local_file))[0]
                    if mimetype:
                        headers["Content-Type"] = mimetype

                    try:
                        contents = local_file.read_bytes()
                    except OSError as e:
                        logging.warning(f"Could not read file: {e}")
                        continue

                    flow.response = http.Response.make(200, contents, headers)
                    # only set flow.response once, for the first matching rule
                    return
        if all_candidates:
            flow.response = http.Response.make(404)
            logging.info(
                f"None of the local file candidates exist: {', '.join(str(x) for x in all_candidates)}"
            )
