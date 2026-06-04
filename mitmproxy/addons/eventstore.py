"""
把日志事件保存在内存中的 UI 支撑 addon。

触发点：
- logging `emit`：日志系统产生记录时由 `CallbackLogger` 接收。
- `eventstore.clear` 命令：清空内存日志。
- `done`：mitmproxy 关闭时卸载日志 handler。
- 本 addon 不监听网络生命周期事件。
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
    维护固定长度的日志环形缓冲区，并通过 signal 通知 UI 刷新。
    """

    def __init__(self, size: int = 10000) -> None:
        """
        初始化日志缓冲区并安装回调式 logging handler。
        """
        self.data: collections.deque[LogEntry] = collections.deque(maxlen=size)
        self.sig_add = signals.SyncSignal(lambda entry: None)
        self.sig_refresh = signals.SyncSignal(lambda: None)

        self.logger = CallbackLogger(self._add_log)
        self.logger.install()

    def done(self):
        """
        `done` 事件：mitmproxy 关闭时触发，卸载 logging handler。
        """
        self.logger.uninstall()

    def _add_log(self, entry: LogEntry) -> None:
        """
        logging handler 回调：把新日志加入缓冲区并发送新增信号。
        """
        self.data.append(entry)
        self.sig_add.send(entry)

    @property
    def size(self) -> int | None:
        """
        返回日志缓冲区最大容量。
        """
        return self.data.maxlen

    @command.command("eventstore.clear")
    def clear(self) -> None:
        """
        Clear the event log.
        
        中文说明：命令触发点是 `eventstore.clear`，清空后发送 refresh 信号。
        """
        self.data.clear()
        self.sig_refresh.send()


class CallbackLogger(log.MitmLogHandler):
    """
    把 Python logging 记录转发给事件存储回调的 handler。
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
        logging `emit` 回调：格式化日志并安全投递回主事件循环。
        """
        entry = LogEntry(
            msg=self.format(record),
            level=log.LOGGING_LEVELS_TO_LOGENTRY.get(record.levelno, "error"),
        )
        self.event_loop.call_soon_threadsafe(self.callback, entry)
