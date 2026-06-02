"""
`mitmproxy.addons.readfile` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    def __init__(self):
        """
        初始化对象状态。
        """
        self.filter = None
        self._read_task: asyncio.Task | None = None

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option("rfile", Optional[str], None, "Read flows from file.")
        loader.add_option(
            "readfile_filter", Optional[str], None, "Read only matching flows."
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        加载外部文件或配置，并转换为 addon 可处理的数据。
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
        加载外部文件或配置，并转换为 addon 可处理的数据。
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
        `readfile` addon 中的方法，用于处理 `doread` 相关逻辑。
        """
        try:
            await self.load_flows_from_path(rfile)
        except exceptions.FlowReadException as e:
            logger.exception(f"Failed to read {ctx.options.rfile}: {e}")

    def running(self):
        """
        在 mitmproxy 完成启动后执行运行期初始化。
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
        `readfile` addon 中的方法，用于处理 `reading` 相关逻辑。
        """
        return bool(self._read_task and not self._read_task.done())


class ReadFileStdin(ReadFile):
    """
    Support the special case of "-" for reading from stdin
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    async def load_flows_from_path(self, path: str) -> int:
        """
        加载外部文件或配置，并转换为 addon 可处理的数据。
        """
        if path == "-":  # pragma: no cover
            # Need to think about how to test this. This function is scheduled
            # onto the event loop, where a sys.stdin mock has no effect.
            return await self.load_flows(sys.stdin.buffer)
        else:
            return await super().load_flows_from_path(path)
