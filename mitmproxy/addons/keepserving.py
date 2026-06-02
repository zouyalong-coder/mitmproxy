"""
`mitmproxy.addons.keepserving` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from __future__ import annotations

import asyncio

from mitmproxy import ctx
from mitmproxy.utils import asyncio_utils


class KeepServing:
    """
    `keepserving` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "keepserving",
            bool,
            False,
            """
            Continue serving after client playback, server playback or file
            read. This option is ignored by interactive tools, which always keep
            serving.
            """,
        )

    def keepgoing(self) -> bool:
        # Checking for proxyserver.active_connections is important for server replay,
        # the addon may report that replay is finished but not the entire response has been sent yet.
        # (https://github.com/mitmproxy/mitmproxy/issues/7569)
        """
        `keepserving` addon 中的方法，用于处理 `keepgoing` 相关逻辑。
        """
        checks = [
            "readfile.reading",
            "replay.client.count",
            "replay.server.count",
            "proxyserver.active_connections",
        ]
        return any([ctx.master.commands.call(c) for c in checks])

    def shutdown(self):  # pragma: no cover
        """
        `keepserving` addon 中的方法，用于处理 `shutdown` 相关逻辑。
        """
        ctx.master.shutdown()

    async def watch(self):
        """
        `keepserving` addon 中的方法，用于处理 `watch` 相关逻辑。
        """
        while True:
            await asyncio.sleep(0.1)
            if not self.keepgoing():
                self.shutdown()

    def running(self):
        """
        在 mitmproxy 完成启动后执行运行期初始化。
        """
        opts = [
            ctx.options.client_replay,
            ctx.options.server_replay,
            ctx.options.rfile,
        ]
        if any(opts) and not ctx.options.keepserving:
            asyncio_utils.create_task(
                self.watch(),
                name="keepserving",
                keep_ref=True,
            )
