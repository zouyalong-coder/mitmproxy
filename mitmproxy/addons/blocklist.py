"""
`mitmproxy.addons.blocklist` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    表示 blocklist 中的一条过滤规则和对应状态码。
    """
    matches: flowfilter.TFilter
    status_code: int


def parse_spec(option: str) -> BlockSpec:
    """
    Parses strings in the following format, enforces number of segments:

        /flow-filter/status

    中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
    `blocklist` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.items: list[BlockSpec] = []

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
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
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
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
