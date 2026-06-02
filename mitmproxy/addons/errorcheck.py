"""
`mitmproxy.addons.errorcheck` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import asyncio
import logging
import sys

from mitmproxy import log
from mitmproxy.contrib import click as miniclick
from mitmproxy.utils import vt_codes


class ErrorCheck:
    """
    Monitor startup for error log entries, and terminate immediately if there are some.
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    repeat_errors_on_stderr: bool
    """
    Repeat all errors on stderr before exiting.
    This is useful for the console UI, which otherwise swallows all output.
    """

    def __init__(self, repeat_errors_on_stderr: bool = False) -> None:
        """
        初始化对象状态。
        """
        self.repeat_errors_on_stderr = repeat_errors_on_stderr

        self.logger = ErrorCheckHandler()
        self.logger.install()

    def finish(self):
        """
        `errorcheck` addon 中的方法，用于处理 `finish` 相关逻辑。
        """
        self.logger.uninstall()

    async def shutdown_if_errored(self):
        # don't run immediately, wait for all logging tasks to finish.
        """
        `errorcheck` addon 中的方法，用于处理 `shutdown if errored` 相关逻辑。
        """
        await asyncio.sleep(0)
        if self.logger.has_errored:
            plural = "s" if len(self.logger.has_errored) > 1 else ""
            if self.repeat_errors_on_stderr:
                message = f"Error{plural} logged during startup:"
                if vt_codes.ensure_supported(sys.stderr):  # pragma: no cover
                    message = miniclick.style(message, fg="red")
                details = "\n".join(
                    self.logger.format(r) for r in self.logger.has_errored
                )
                print(f"{message}\n{details}", file=sys.stderr)
            else:
                print(
                    f"Error{plural} logged during startup, exiting...", file=sys.stderr
                )

            sys.exit(1)


class ErrorCheckHandler(log.MitmLogHandler):
    """
    收集启动或运行期错误的日志处理器。
    """
    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        super().__init__(logging.ERROR)
        self.has_errored: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """
        `errorcheck` addon 中的方法，用于处理 `emit` 相关逻辑。
        """
        self.has_errored.append(record)
