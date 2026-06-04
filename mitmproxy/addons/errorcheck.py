"""
启动期错误检测 addon。

触发点：
- logging `emit`：启动期间出现 ERROR 级别日志时收集记录。
- `finish`：启动检查结束时卸载 handler。
- `shutdown_if_errored`：启动日志任务完成后检查是否需要退出进程。
- 本 addon 不监听网络生命周期事件。
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
    
    中文说明：用于命令行启动阶段。如果初始化期间出现错误日志，就尽早退出，
    避免 mitmproxy 在半失败状态下继续运行。
    """

    repeat_errors_on_stderr: bool
    """
    Repeat all errors on stderr before exiting.
    This is useful for the console UI, which otherwise swallows all output.
    """

    def __init__(self, repeat_errors_on_stderr: bool = False) -> None:
        """
        初始化错误收集 handler，并决定退出前是否把错误重复输出到 stderr。
        """
        self.repeat_errors_on_stderr = repeat_errors_on_stderr

        self.logger = ErrorCheckHandler()
        self.logger.install()

    def finish(self):
        """
        启动检查结束入口：卸载错误收集 handler。
        """
        self.logger.uninstall()

    async def shutdown_if_errored(self):
        # don't run immediately, wait for all logging tasks to finish.
        """
        异步退出检查：等待日志任务刷新后，如果收集到错误则退出进程。
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
    收集 ERROR 级别日志的 logging handler。
    """

    def __init__(self) -> None:
        """
        初始化错误记录列表。
        """
        super().__init__(logging.ERROR)
        self.has_errored: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """
        logging `emit` 回调：保存一条 ERROR 日志记录。
        """
        self.has_errored.append(record)
