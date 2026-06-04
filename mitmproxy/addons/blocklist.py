"""
按 flow filter 匹配并阻断 HTTP 请求的内置 addon。

触发点：
- `load`：addon 加载时注册 `block_list` 选项。
- `configure`：`block_list` 变化时重新解析规则。
- `request`：每个 HTTP 请求发往上游前触发，匹配规则后直接返回响应或关闭连接。
"""

from collections.abc import Sequence
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import version
from mitmproxy.net.http.status_codes import NO_RESPONSE


class BlockSpec(NamedTuple):
    """
    表示 blocklist 中的一条规则。

    `matches` 是已编译的 flow filter，`status_code` 是命中后返回的状态码；
    特殊状态码 444 表示不发送 HTTP 响应、直接关闭连接。
    """
    matches: flowfilter.TFilter
    status_code: int


def parse_spec(option: str) -> BlockSpec:
    """
    Parses strings in the following format, enforces number of segments:

        /flow-filter/status

    中文说明：把用户配置的单条字符串解析为 `BlockSpec`。分隔符取配置的第
    一个字符，因此 `/~u example/403` 和 `|~u example|403` 都是合法形式。
    """
    sep, rem = option[0], option[1:]

    parts = rem.split(sep, 2)
    if len(parts) != 2:
        raise ValueError("Invalid number of parameters (2 are expected)")
    flow_patt, status = parts
    try:
        status_code = int(status)
    except ValueError:
        raise ValueError(f"Invalid HTTP status code: {status}")
    flow_filter = flowfilter.parse(flow_patt)

    return BlockSpec(matches=flow_filter, status_code=status_code)


class BlockList:
    """
    缓存并执行 block_list 规则。
    """

    def __init__(self) -> None:
        """
        初始化规则缓存。
        """
        self.items: list[BlockSpec] = []

    def load(self, loader):
        """
        addon 加载事件：注册 `block_list` 规则列表。
        """
        loader.add_option(
            "block_list",
            Sequence[str],
            [],
            """
            Block matching requests and return an empty response with the specified HTTP status.
            Option syntax is "/flow-filter/status-code", where flow-filter describes
            which requests this rule should be applied to and status-code is the HTTP status code to return for
            blocked requests. The separator ("/" in the example) can be any character.
            Setting a non-standard status code of 444 will close the connection without sending a response.
            """,
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        只有 `block_list` 更新时才重新解析，解析失败会抛出 OptionsError，使
        本次配置变更回滚。
        """
        if "block_list" in updated:
            self.items = []
            for option in ctx.options.block_list:
                try:
                    spec = parse_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse block_list option {option}: {e}"
                    ) from e
                self.items.append(spec)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        HTTP `request` 事件：请求发往上游前触发。

        仅处理仍然 live、尚无 response/error 的请求；命中规则后设置
        `flow.metadata["blocklisted"]` 方便 UI 或其他 addon 识别。
        """
        if flow.response or flow.error or not flow.live:
            return

        for spec in self.items:
            if spec.matches(flow):
                flow.metadata["blocklisted"] = True
                if spec.status_code == NO_RESPONSE:
                    flow.kill()
                else:
                    flow.response = http.Response.make(
                        spec.status_code, headers={"Server": version.MITMPROXY}
                    )
