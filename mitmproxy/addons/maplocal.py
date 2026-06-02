"""
`mitmproxy.addons.maplocal` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    表示 map-local 的匹配规则和本地文件系统目标。
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
    """Join a Path element with an untrusted str.

    This is a convenience wrapper for werkzeug's safe_join,
    raising a ValueError if the path is malformed.
    raising a ValueError if the path is malformed.中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
    raising a ValueError if the path is malformed."""
    untrusted_parts = Path(untrusted).parts
    joined = safe_join(root.as_posix(), *untrusted_parts)
    if joined is None:
        raise ValueError("Untrusted paths.")
    return Path(joined)


def file_candidates(url: str, spec: MapLocalSpec) -> list[Path]:
    """
    Get all potential file candidates given a URL and a mapping spec ordered by preference.
    This function already assumes that the spec regex matches the URL.
    
    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
    `maplocal` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.replacements: list[MapLocalSpec] = []

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
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
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
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
