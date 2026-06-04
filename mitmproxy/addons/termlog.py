"""
把日志输出到终端的内置 addon。

触发点：
- `load`：注册终端日志级别选项。
- `configure`：`termlog_verbosity` 变化时调整 handler 级别。
- logging `emit`：日志系统产生记录时写入 stdout。
- `uninstall`：mitmproxy 收尾阶段卸载 handler。
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import IO

from mitmproxy import ctx
from mitmproxy import log
from mitmproxy.utils import vt_codes


class TermLog:
    """
    安装并管理面向终端输出的 logging handler。
    """
    _teardown_task: asyncio.Task | None = None

    def __init__(self, out: IO[str] | None = None):
        """
        初始化终端日志 handler 并立即安装。
        """
        self.logger = TermLogHandler(out)
        self.logger.install()

    def load(self, loader):
        """
        addon 加载事件：注册 `termlog_verbosity` 并设置默认日志级别。
        """
        loader.add_option(
            "termlog_verbosity", str, "info", "Log verbosity.", choices=log.LogLevels
        )
        self.logger.setLevel(logging.INFO)

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发，更新终端日志级别。
        """
        if "termlog_verbosity" in updated:
            self.logger.setLevel(ctx.options.termlog_verbosity.upper())

    def uninstall(self) -> None:
        # uninstall the log dumper.
        # This happens at the very very end after done() is completed,
        # because we don't want to uninstall while other addons are still logging.
        """
        收尾卸载入口：在其他 addon 的 `done()` 之后卸载日志 handler。
        """
        self.logger.uninstall()


class TermLogHandler(log.MitmLogHandler):
    """
    把 logging 记录格式化并写入终端的处理器。
    """
    def __init__(self, out: IO[str] | None = None):
        """
        初始化输出流、颜色支持和 formatter。
        """
        super().__init__()
        self.file: IO[str] = out or sys.stdout
        self.has_vt_codes = vt_codes.ensure_supported(self.file)
        self.formatter = log.MitmFormatter(self.has_vt_codes)

    def emit(self, record: logging.LogRecord) -> None:
        """
        logging `emit` 回调：把一条日志记录写入终端。
        """
        try:
            print(self.format(record), file=self.file)
        except OSError:
            # We cannot print, exit immediately.
            # See https://github.com/mitmproxy/mitmproxy/issues/4669
            sys.exit(1)
