"""
`mitmproxy.addons.termlog` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    `termlog` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    _teardown_task: asyncio.Task | None = None

    def __init__(self, out: IO[str] | None = None):
        """
        初始化对象状态。
        """
        self.logger = TermLogHandler(out)
        self.logger.install()

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "termlog_verbosity", str, "info", "Log verbosity.", choices=log.LogLevels
        )
        self.logger.setLevel(logging.INFO)

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "termlog_verbosity" in updated:
            self.logger.setLevel(ctx.options.termlog_verbosity.upper())

    def uninstall(self) -> None:
        # uninstall the log dumper.
        # This happens at the very very end after done() is completed,
        # because we don't want to uninstall while other addons are still logging.
        """
        `termlog` addon 中的方法，用于处理 `uninstall` 相关逻辑。
        """
        self.logger.uninstall()


class TermLogHandler(log.MitmLogHandler):
    """
    把 logging 记录写入终端日志 addon 的处理器。
    """
    def __init__(self, out: IO[str] | None = None):
        """
        初始化对象状态。
        """
        super().__init__()
        self.file: IO[str] = out or sys.stdout
        self.has_vt_codes = vt_codes.ensure_supported(self.file)
        self.formatter = log.MitmFormatter(self.has_vt_codes)

    def emit(self, record: logging.LogRecord) -> None:
        """
        `termlog` addon 中的方法，用于处理 `emit` 相关逻辑。
        """
        try:
            print(self.format(record), file=self.file)
        except OSError:
            # We cannot print, exit immediately.
            # See https://github.com/mitmproxy/mitmproxy/issues/4669
            sys.exit(1)
