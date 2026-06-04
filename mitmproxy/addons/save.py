"""
把 flow 保存为 mitmproxy dump 文件的内置 addon。

触发点：
- `load/configure`：注册并应用 `save_stream_file`、`save_stream_filter`。
- `save.file` 命令：用户显式保存选中的 flows。
- HTTP：`request` 记录活跃 flow，`response/error/websocket_end` 写入文件。
- TCP/UDP：`*_start` 记录活跃 flow，`*_end/*_error` 写入文件。
- DNS：`dns_request` 记录活跃 flow，`dns_response/dns_error` 写入文件。
- `done`：mitmproxy 关闭时写出仍活跃的流并关闭文件。
"""

import logging
import os.path
import sys
from collections.abc import Sequence
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal
from typing import Optional

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import io
from mitmproxy import tcp
from mitmproxy import udp
from mitmproxy.log import ALERT


@lru_cache
def _path(path: str) -> str:
    """
    Extract the path from a path spec (which may have an extra "+" at the front)
    
    中文说明：去掉路径前缀 `+` 并展开用户目录；`+` 只表示追加模式，不属于
    真实文件路径。
    """
    if path.startswith("+"):
        path = path[1:]
    return os.path.expanduser(path)


@lru_cache
def _mode(path: str) -> Literal["ab", "wb"]:
    """
    Extract the writing mode (overwrite or append) from a path spec
    
    中文说明：路径以 `+` 开头表示追加到已有 dump 文件，否则覆盖写入。
    """
    if path.startswith("+"):
        return "ab"
    else:
        return "wb"


class Save:
    """
    管理流式保存文件、过滤器和仍未结束的活跃 flow 集合。
    """

    def __init__(self) -> None:
        """
        初始化输出流、过滤器和活跃 flow 集合。
        """
        self.stream: io.FilteredFlowWriter | None = None
        self.filt: flowfilter.TFilter | None = None
        self.active_flows: set[flow.Flow] = set()
        self.current_path: str | None = None

    def load(self, loader):
        """
        addon 加载事件：注册流式保存相关选项。
        """
        loader.add_option(
            "save_stream_file",
            Optional[str],
            None,
            """
            Stream flows to file as they arrive. Prefix path with + to append.
            The full path can use python strftime() formating, missing
            directories are created as needed. A new file is opened every time
            the formatted string changes.
            """,
        )
        loader.add_option(
            "save_stream_filter",
            Optional[str],
            None,
            "Filter which flows are written to file.",
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        更新过滤器或输出文件；如果路径使用 strftime 模板，会在写入前按当前
        时间决定是否轮换到新文件。
        """
        if "save_stream_filter" in updated:
            if ctx.options.save_stream_filter:
                try:
                    self.filt = flowfilter.parse(ctx.options.save_stream_filter)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            else:
                self.filt = None
        if "save_stream_file" in updated or "save_stream_filter" in updated:
            if ctx.options.save_stream_file:
                try:
                    self.maybe_rotate_to_new_file()
                except OSError as e:
                    raise exceptions.OptionsError(str(e)) from e
                assert self.stream
                self.stream.flt = self.filt
            else:
                self.done()

    def maybe_rotate_to_new_file(self) -> None:
        """
        根据 `save_stream_file` 的 strftime 模板决定是否切换输出文件。
        """
        path = datetime.today().strftime(_path(ctx.options.save_stream_file))
        if self.current_path == path:
            return

        if self.stream:
            self.stream.fo.close()
            self.stream = None

        new_log_file = Path(path)
        new_log_file.parent.mkdir(parents=True, exist_ok=True)

        f = new_log_file.open(_mode(ctx.options.save_stream_file))
        self.stream = io.FilteredFlowWriter(f, self.filt)
        self.current_path = path

    def save_flow(self, flow: flow.Flow) -> None:
        """
        Write the flow to the stream, but first check if we need to rotate to a new file.
        
        中文说明：所有协议的结束/错误事件最终都会走到这里。写入前会检查是否
        需要轮换文件，写入成功后从 `active_flows` 移除。
        """
        if not self.stream:
            return
        try:
            self.maybe_rotate_to_new_file()
            self.stream.add(flow)
        except OSError as e:
            # If we somehow fail to write flows to a logfile, we really want to crash visibly
            # instead of letting traffic through unrecorded.
            # No normal logging here, that would not be triggered anymore.
            sys.stderr.write(f"Error while writing to {self.current_path}: {e}")
            sys.exit(1)
        else:
            self.active_flows.discard(flow)

    def done(self) -> None:
        """
        在 addon 或 mitmproxy 关闭时释放资源并做收尾处理。
        """
        if self.stream:
            for f in self.active_flows:
                self.stream.add(f)
            self.active_flows.clear()

            self.current_path = None
            self.stream.fo.close()
            self.stream = None

    @command.command("save.file")
    def save(self, flows: Sequence[flow.Flow], path: mitmproxy.types.Path) -> None:
        """
        Save flows to a file. If the path starts with a +, flows are
        appended to the file, otherwise it is over-written.
        
        中文说明：命令触发点是 `save.file`，用于一次性保存用户选中的 flows。
        """
        try:
            with open(_path(path), _mode(path)) as f:
                stream = io.FlowWriter(f)
                for i in flows:
                    stream.add(i)
        except OSError as e:
            raise exceptions.CommandError(e) from e
        if path.endswith(".har") or path.endswith(".zhar"):  # pragma: no cover
            logging.log(
                ALERT,
                f"Saved as mitmproxy dump file. To save HAR files, use the `save.har` command.",
            )
        else:
            logging.log(ALERT, f"Saved {len(flows)} flows.")

    def tcp_start(self, flow: tcp.TCPFlow):
        """
        TCP `tcp_start` 事件：TCP flow 创建时触发，先加入活跃集合。
        """
        if self.stream:
            self.active_flows.add(flow)

    def tcp_end(self, flow: tcp.TCPFlow):
        """
        TCP `tcp_end` 事件：TCP flow 正常结束时触发，写入 dump。
        """
        self.save_flow(flow)

    def tcp_error(self, flow: tcp.TCPFlow):
        """
        TCP `tcp_error` 事件：TCP flow 出错时触发，按结束流程写入 dump。
        """
        self.tcp_end(flow)

    def udp_start(self, flow: udp.UDPFlow):
        """
        UDP `udp_start` 事件：UDP flow 创建时触发，先加入活跃集合。
        """
        if self.stream:
            self.active_flows.add(flow)

    def udp_end(self, flow: udp.UDPFlow):
        """
        UDP `udp_end` 事件：UDP flow 正常结束时触发，写入 dump。
        """
        self.save_flow(flow)

    def udp_error(self, flow: udp.UDPFlow):
        """
        UDP `udp_error` 事件：UDP flow 出错时触发，按结束流程写入 dump。
        """
        self.udp_end(flow)

    def websocket_end(self, flow: http.HTTPFlow):
        """
        WebSocket `websocket_end` 事件：升级后的 WebSocket 连接结束时触发。
        """
        self.save_flow(flow)

    def request(self, flow: http.HTTPFlow):
        """
        HTTP `request` 事件：请求发往上游前触发，先加入活跃集合。
        """
        if self.stream:
            self.active_flows.add(flow)

    def response(self, flow: http.HTTPFlow):
        # websocket flows will receive a websocket_end,
        # we don't want to persist them here already
        """
        HTTP `response` 事件：响应返回客户端前触发。

        普通 HTTP flow 在这里写入；WebSocket flow 等 `websocket_end`，避免过早
        保存尚未完成的消息列表。
        """
        if flow.websocket is None:
            self.save_flow(flow)

    def error(self, flow: http.HTTPFlow):
        """
        HTTP `error` 事件：HTTP flow 发生连接或协议错误时触发，按响应流程写入。
        """
        self.response(flow)

    def dns_request(self, flow: dns.DNSFlow):
        """
        DNS `dns_request` 事件：DNS 请求进入代理时触发，先加入活跃集合。
        """
        if self.stream:
            self.active_flows.add(flow)

    def dns_response(self, flow: dns.DNSFlow):
        """
        DNS `dns_response` 事件：DNS 响应返回客户端前触发，写入 dump。
        """
        self.save_flow(flow)

    def dns_error(self, flow: dns.DNSFlow):
        """
        DNS `dns_error` 事件：DNS flow 出错时触发，写入 dump。
        """
        self.save_flow(flow)
