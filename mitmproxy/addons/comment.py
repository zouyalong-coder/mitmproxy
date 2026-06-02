"""
`mitmproxy.addons.comment` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from collections.abc import Sequence

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy.hooks import UpdateHook


class Comment:
    """
    `comment` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """

    @command.command("flow.comment")
    def comment(self, flow: Sequence[flow.Flow], comment: str) -> None:
        """
        Add a comment to a flow

        中文说明：为指定 flow 写入用户备注，并触发更新事件通知界面或其他 addon。
        """

        updated = []
        for f in flow:
            f.comment = comment
            updated.append(f)

        ctx.master.addons.trigger(UpdateHook(updated))
