"""
`mitmproxy.addons.command_history` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import logging
import os
import pathlib
from collections.abc import Sequence

from mitmproxy import command
from mitmproxy import ctx


class CommandHistory:
    """
    维护 `command_history` addon 的内存状态或历史记录。
    """
    VACUUM_SIZE = 1024

    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        self.history: list[str] = []
        self.filtered_history: list[str] = [""]
        self.current_index: int = 0

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "command_history",
            bool,
            True,
            """Persist command history between mitmproxy invocations.""",
        )

    @property
    def history_file(self) -> pathlib.Path:
        """
        `command_history` addon 中的方法，用于处理 `history file` 相关逻辑。
        """
        return pathlib.Path(os.path.expanduser(ctx.options.confdir)) / "command_history"

    def running(self):
        # FIXME: We have a weird bug where the contract for configure is not followed and it is never called with
        # confdir or command_history as updated.
        """
        在 mitmproxy 完成启动后执行运行期初始化。
        """
        self.configure("command_history")  # pragma: no cover

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "command_history" in updated or "confdir" in updated:
            if ctx.options.command_history and self.history_file.is_file():
                self.history = self.history_file.read_text().splitlines()
                self.set_filter("")

    def done(self):
        """
        在 addon 或 mitmproxy 关闭时释放资源并做收尾处理。
        """
        if ctx.options.command_history and len(self.history) >= self.VACUUM_SIZE:
            # vacuum history so that it doesn't grow indefinitely.
            history_str = "\n".join(self.history[-self.VACUUM_SIZE // 2 :]) + "\n"
            try:
                self.history_file.write_text(history_str)
            except Exception as e:
                logging.warning(f"Failed writing to {self.history_file}: {e}")

    @command.command("commands.history.add")
    def add_command(self, command: str) -> None:
        """
        `command_history` addon 中的方法，用于处理 `add command` 相关逻辑。
        """
        if not command.strip():
            return

        self.history.append(command)
        if ctx.options.command_history:
            try:
                with self.history_file.open("a") as f:
                    f.write(f"{command}\n")
            except Exception as e:
                logging.warning(f"Failed writing to {self.history_file}: {e}")

        self.set_filter("")

    @command.command("commands.history.get")
    def get_history(self) -> Sequence[str]:
        """
        Get the entire command history.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        return self.history.copy()

    @command.command("commands.history.clear")
    def clear_history(self):
        """
        `command_history` addon 中的方法，用于处理 `clear history` 相关逻辑。
        """
        if self.history_file.exists():
            try:
                self.history_file.unlink()
            except Exception as e:
                logging.warning(f"Failed deleting {self.history_file}: {e}")
        self.history = []
        self.set_filter("")

    # Functionality to provide a filtered list that can be iterated through.

    @command.command("commands.history.filter")
    def set_filter(self, prefix: str) -> None:
        """
        更新当前 addon 状态中的指定数据。
        """
        self.filtered_history = [cmd for cmd in self.history if cmd.startswith(prefix)]
        self.filtered_history.append(prefix)
        self.current_index = len(self.filtered_history) - 1

    @command.command("commands.history.next")
    def get_next(self) -> str:
        """
        读取并返回当前 addon 状态中的指定数据。
        """
        self.current_index = min(self.current_index + 1, len(self.filtered_history) - 1)
        return self.filtered_history[self.current_index]

    @command.command("commands.history.prev")
    def get_prev(self) -> str:
        """
        读取并返回当前 addon 状态中的指定数据。
        """
        self.current_index = max(0, self.current_index - 1)
        return self.filtered_history[self.current_index]
