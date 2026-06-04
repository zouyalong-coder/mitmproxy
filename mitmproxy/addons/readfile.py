"""
启动后从 dump 文件读取 flow 的内置 addon。

触发点：
- `load`：addon 加载时注册 `rfile` 和 `readfile_filter`。
- `configure`：过滤表达式变化时重新解析。
- `running`：mitmproxy 完成启动后触发，按 `rfile` 创建异步读取任务。
- `readfile.reading` 命令：查询当前是否仍在读取。
"""

import asyncio
import logging
import os.path
import sys
from typing import BinaryIO
from typing import Optional

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import io
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class ReadFile:
    """
    An addon that handles reading from file on startup.
    
    中文说明：读取 mitmproxy dump 文件并把其中的 flow 交给 master 注入到当前
    会话中，常用于启动时预加载历史流量。
    """

    def __init__(self):
        """
        初始化可选过滤器和后台读取任务引用。
        """
        self.filter = None
        self._read_task: asyncio.Task | None = None

    def load(self, loader):
        """
        addon 加载事件：注册读取文件路径和读取过滤器。
        """
        loader.add_option("rfile", Optional[str], None, "Read flows from file.")
        loader.add_option(
            "readfile_filter", Optional[str], None, "Read only matching flows."
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        `readfile_filter` 是 flow filter 字符串，解析失败会拒绝本次配置更新。
        """
        if "readfile_filter" in updated:
            if ctx.options.readfile_filter:
                try:
                    self.filter = flowfilter.parse(ctx.options.readfile_filter)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            else:
                self.filter = None

    async def load_flows(self, fo: BinaryIO) -> int:
        """
        从二进制文件对象读取 flow 并逐条交给 master。
        """
        cnt = 0
        freader = io.FlowReader(fo)
        try:
            for flow in freader.stream():
                if self.filter and not self.filter(flow):
                    continue
                await ctx.master.load_flow(flow)
                cnt += 1
        except (OSError, exceptions.FlowReadException) as e:
            if cnt:
                logging.warning("Flow file corrupted - loaded %i flows." % cnt)
            else:
                logging.error("Flow file corrupted.")
            raise exceptions.FlowReadException(str(e)) from e
        else:
            return cnt

    async def load_flows_from_path(self, path: str) -> int:
        """
        展开路径并从 dump 文件读取 flow。
        """
        path = os.path.expanduser(path)
        try:
            with open(path, "rb") as f:
                return await self.load_flows(f)
        except OSError as e:
            logging.error(f"Cannot load flows: {e}")
            raise exceptions.FlowReadException(str(e)) from e

    async def doread(self, rfile: str) -> None:
        """
        后台读取任务入口，捕获并记录读取失败。
        """
        try:
            await self.load_flows_from_path(rfile)
        except exceptions.FlowReadException as e:
            logger.exception(f"Failed to read {ctx.options.rfile}: {e}")

    def running(self):
        """
        `running` 事件：mitmproxy 完成启动后触发。

        如果配置了 `rfile`，就在事件循环中创建读取任务，避免阻塞启动流程。
        """
        if ctx.options.rfile:
            self._read_task = asyncio_utils.create_task(
                self.doread(ctx.options.rfile),
                name="readfile",
                keep_ref=False,
            )

    @command.command("readfile.reading")
    def reading(self) -> bool:
        """
        `readfile.reading` 命令：返回后台读取任务是否仍在运行。
        """
        return bool(self._read_task and not self._read_task.done())


class ReadFileStdin(ReadFile):
    """
    Support the special case of "-" for reading from stdin
    
    中文说明：扩展 `ReadFile`，让 `rfile=-` 时可以从标准输入读取 dump 数据。
    """

    async def load_flows_from_path(self, path: str) -> int:
        """
        从路径或标准输入读取 flow；`-` 表示 stdin。
        """
        if path == "-":  # pragma: no cover
            # Need to think about how to test this. This function is scheduled
            # onto the event loop, where a sys.stdin mock has no effect.
            return await self.load_flows(sys.stdin.buffer)
        else:
            return await super().load_flows_from_path(path)
