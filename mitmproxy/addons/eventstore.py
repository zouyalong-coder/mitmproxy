"""
`mitmproxy.addons.eventstore` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import asyncio
import collections
import logging
from collections.abc import Callable

from mitmproxy import command
from mitmproxy import log
from mitmproxy.log import LogEntry
from mitmproxy.utils import signals


class EventStore:
    """
    维护 `eventstore` addon 的内存状态或历史记录。
    """
    def __init__(self, size: int = 10000) -> None:
        """
        初始化对象状态。
        """
        self.data: collections.deque[LogEntry] = collections.deque(maxlen=size)
        self.sig_add = signals.SyncSignal(lambda entry: None)
        self.sig_refresh = signals.SyncSignal(lambda: None)

        self.logger = CallbackLogger(self._add_log)
        self.logger.install()

    def done(self):
        """
        在 addon 或 mitmproxy 关闭时释放资源并做收尾处理。
        """
        self.logger.uninstall()

    def _add_log(self, entry: LogEntry) -> None:
        """
        `eventstore` addon 的内部辅助方法。
        """
        self.data.append(entry)
        self.sig_add.send(entry)

    @property
    def size(self) -> int | None:
        """
        `eventstore` addon 中的方法，用于处理 `size` 相关逻辑。
        """
        return self.data.maxlen

    @command.command("eventstore.clear")
    def clear(self) -> None:
        """
        Clear the event log.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        self.data.clear()
        self.sig_refresh.send()


class CallbackLogger(log.MitmLogHandler):
    """
    把日志记录转发给回调函数的 logging handler。
    """
    def __init__(
        self,
        callback: Callable[[LogEntry], None],
    ):
        """
        初始化对象状态。
        """
        super().__init__()
        self.callback = callback
        self.event_loop = asyncio.get_running_loop()
        self.formatter = log.MitmFormatter(colorize=False)

    def emit(self, record: logging.LogRecord) -> None:
        """
        `eventstore` addon 中的方法，用于处理 `emit` 相关逻辑。
        """
        entry = LogEntry(
            msg=self.format(record),
            level=log.LOGGING_LEVELS_TO_LOGENTRY.get(record.levelno, "error"),
        )
        self.event_loop.call_soon_threadsafe(self.callback, entry)
