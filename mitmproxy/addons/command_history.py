"""
保存和检索命令历史的 UI 支撑 addon。

触发点：
- `load`：注册 `command_history` 开关。
- `running/configure`：启动后或配置变化时读取历史文件。
- `done`：关闭时压缩过大的历史文件。
- `commands.history.*` 命令：由命令输入 UI 调用。
"""

import logging
import os
import pathlib
from collections.abc import Sequence

from mitmproxy import command
from mitmproxy import ctx


class CommandHistory:
    """
    维护内存命令历史、前缀过滤结果和持久化文件。
    """
    VACUUM_SIZE = 1024

    def __init__(self) -> None:
        """
        初始化历史列表、过滤列表和当前浏览位置。
        """
        self.history: list[str] = []
        self.filtered_history: list[str] = [""]
        self.current_index: int = 0

    def load(self, loader):
        """
        addon 加载事件：注册是否持久化命令历史的开关。
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
        返回当前配置目录下的命令历史文件路径。
        """
        return pathlib.Path(os.path.expanduser(ctx.options.confdir)) / "command_history"

    def running(self):
        # FIXME: We have a weird bug where the contract for configure is not followed and it is never called with
        # confdir or command_history as updated.
        """
        `running` 事件：mitmproxy 启动完成后触发，用于读取已有历史文件。
        """
        self.configure("command_history")  # pragma: no cover

    def configure(self, updated):
        """
        `configure` 事件：相关选项变化后触发，重新读取历史文件并刷新过滤器。
        """
        if "command_history" in updated or "confdir" in updated:
            if ctx.options.command_history and self.history_file.is_file():
                self.history = self.history_file.read_text().splitlines()
                self.set_filter("")

    def done(self):
        """
        `done` 事件：mitmproxy 关闭时触发，必要时裁剪历史文件避免无限增长。
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
        `commands.history.add` 命令：记录一条新执行的命令。
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
        
        中文说明：命令触发点是 `commands.history.get`，返回历史副本供 UI 展示。
        """
        return self.history.copy()

    @command.command("commands.history.clear")
    def clear_history(self):
        """
        `commands.history.clear` 命令：删除持久化文件并清空内存历史。
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
        `commands.history.filter` 命令：按当前输入前缀生成可上下浏览的历史列表。
        """
        self.filtered_history = [cmd for cmd in self.history if cmd.startswith(prefix)]
        self.filtered_history.append(prefix)
        self.current_index = len(self.filtered_history) - 1

    @command.command("commands.history.next")
    def get_next(self) -> str:
        """
        `commands.history.next` 命令：返回过滤历史中的下一条。
        """
        self.current_index = min(self.current_index + 1, len(self.filtered_history) - 1)
        return self.filtered_history[self.current_index]

    @command.command("commands.history.prev")
    def get_prev(self) -> str:
        """
        `commands.history.prev` 命令：返回过滤历史中的上一条。
        """
        self.current_index = max(0, self.current_index - 1)
        return self.filtered_history[self.current_index]
