"""
为 flow 写入备注的命令型 addon。

触发点：
- `flow.comment` 命令：由控制台、Web UI 或其他 addon 调用。
- 本 addon 不监听网络生命周期事件；写入后主动触发 `UpdateHook` 通知界面刷新。
"""

from collections.abc import Sequence

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy.hooks import UpdateHook


class Comment:
    """
    提供 `flow.comment` 命令，用于给一组 flow 设置相同备注。
    """

    @command.command("flow.comment")
    def comment(self, flow: Sequence[flow.Flow], comment: str) -> None:
        """
        Add a comment to a flow

        中文说明：命令触发点是 `flow.comment`。它不是自动 hook，而是用户或 UI
        显式调用；修改完成后通过 `UpdateHook` 广播受影响的 flow。
        """

        updated = []
        for f in flow:
            f.comment = comment
            updated.append(f)

        ctx.master.addons.trigger(UpdateHook(updated))
