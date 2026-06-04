"""
批处理模式下决定任务完成后是否自动退出的 addon。

触发点：
- `load`：注册 `keepserving` 选项。
- `running`：mitmproxy 启动完成后，如果存在读取/回放任务且未要求持续服务，则启动 watcher。
- `watch`：后台任务定期轮询 readfile/replay/proxyserver 命令，任务结束后调用 shutdown。
"""

from __future__ import annotations

import asyncio

from mitmproxy import ctx
from mitmproxy.utils import asyncio_utils


class KeepServing:
    """
    监控批处理任务是否完成，并在适当时关闭 mitmproxy。
    """

    def load(self, loader):
        """
        addon 加载事件：注册是否在批处理任务后继续服务的开关。
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
        判断当前是否仍有读取、重放或活跃代理连接需要等待。

        这里通过命令系统查询其他 addon 状态，避免直接依赖它们的内部字段。
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
        触发 master 关闭。
        """
        ctx.master.shutdown()

    async def watch(self):
        """
        后台 watcher：定期检查是否还需要继续运行，不需要时关闭 master。
        """
        while True:
            await asyncio.sleep(0.1)
            if not self.keepgoing():
                self.shutdown()

    def running(self):
        """
        `running` 事件：mitmproxy 启动完成后触发。

        只有在配置了 client replay、server replay 或 rfile 且未开启 keepserving
        时，才启动自动退出 watcher。
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
