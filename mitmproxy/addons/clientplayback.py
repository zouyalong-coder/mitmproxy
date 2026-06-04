"""
客户端重放 addon：把已有 HTTP flow 的请求重新发送到服务器。

触发点：
- `running`：mitmproxy 启动完成后创建后台重放队列消费者。
- `configure`：`client_replay` 变化时从文件读取 flow 并入队。
- `replay.client*` 命令：查询、停止、添加或从文件加载重放任务。
- 内部 `ReplayHandler.handle_hook`：重放过程中继续触发正常 HTTP 生命周期 hook。
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from types import TracebackType
from typing import cast
from typing import Literal

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import io
from mitmproxy.connection import ConnectionState
from mitmproxy.connection import Server
from mitmproxy.hooks import UpdateHook
from mitmproxy.log import ALERT
from mitmproxy.options import Options
from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layers
from mitmproxy.proxy import server
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import CommandGenerator
from mitmproxy.proxy.layers.http import HTTPMode
from mitmproxy.proxy.mode_specs import UpstreamMode
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class MockServer(layers.http.HttpConnection):
    """
    A mock HTTP "server" that just pretends it received a full HTTP request,
    which is then processed by the proxy core.
    
    中文说明：它不连接真实客户端，而是把待重放 flow 的请求伪装成代理核心收到
    的完整 HTTP 请求，让后续代理层按普通请求处理。
    """

    flow: http.HTTPFlow

    def __init__(self, flow: http.HTTPFlow, context: Context):
        """
        初始化伪造的 HTTP 服务端层，保存待注入的请求 flow。
        """
        super().__init__(context, context.client)
        self.flow = flow

    def _handle_event(self, event: events.Event) -> CommandGenerator[None]:
        """
        代理层事件入口。

        收到 `Start` 时把保存的请求头、请求体和 trailers 注入 HTTP 层；收到
        响应相关事件时忽略，因为重放只关心请求被重新发出。
        """
        if isinstance(event, events.Start):
            content = self.flow.request.raw_content
            self.flow.request.timestamp_start = self.flow.request.timestamp_end = (
                time.time()
            )
            yield layers.http.ReceiveHttp(
                layers.http.RequestHeaders(
                    1,
                    self.flow.request,
                    end_stream=not (content or self.flow.request.trailers),
                    replay_flow=self.flow,
                )
            )
            if content:
                yield layers.http.ReceiveHttp(layers.http.RequestData(1, content))
            if self.flow.request.trailers:  # pragma: no cover
                # TODO: Cover this once we support HTTP/1 trailers.
                yield layers.http.ReceiveHttp(
                    layers.http.RequestTrailers(1, self.flow.request.trailers)
                )
            yield layers.http.ReceiveHttp(layers.http.RequestEndOfMessage(1))
        elif isinstance(
            event,
            (
                layers.http.ResponseHeaders,
                layers.http.ResponseData,
                layers.http.ResponseTrailers,
                layers.http.ResponseEndOfMessage,
                layers.http.ResponseProtocolError,
            ),
        ):
            pass
        else:  # pragma: no cover
            logger.warning(f"Unexpected event during replay: {event}")


class ReplayHandler(server.ConnectionHandler):
    """
    用于执行单条客户端重放请求的连接处理器。

    它构造一套临时 Context/Layer，让重放请求像真实客户端连接一样走代理核心。
    """
    layer: layers.HttpLayer

    def __init__(self, flow: http.HTTPFlow, options: Options) -> None:
        """
        初始化重放连接上下文。

        根据原请求 scheme 设置上游 TLS/SNI，并按当前 upstream 模式决定 HTTP 层
        工作模式。
        """
        client = flow.client_conn.copy()
        client.state = ConnectionState.OPEN

        context = Context(client, options)
        context.server = Server(address=(flow.request.host, flow.request.port))
        if flow.request.scheme == "https":
            context.server.tls = True
            context.server.sni = flow.request.pretty_host
        if options.mode and options.mode[0].startswith("upstream:"):
            mode = UpstreamMode.parse(options.mode[0])
            assert isinstance(mode, UpstreamMode)  # remove once mypy supports Self.
            context.server.via = flow.server_conn.via = (mode.scheme, mode.address)

        super().__init__(context)

        if options.mode and options.mode[0].startswith("upstream:"):
            self.layer = layers.HttpLayer(context, HTTPMode.upstream)
        else:
            self.layer = layers.HttpLayer(context, HTTPMode.transparent)
        self.layer.connections[client] = MockServer(flow, context.fork())
        self.flow = flow
        self.done = asyncio.Event()

    async def replay(self) -> None:
        """
        启动一次重放并等待响应或错误 hook 表示完成。
        """
        await self.server_event(events.Start())
        await self.done.wait()

    def log(
        self,
        message: str,
        level: int = logging.INFO,
        exc_info: Literal[True]
        | tuple[type[BaseException] | None, BaseException | None, TracebackType | None]
        | None = None,
    ) -> None:
        """
        `clientplayback` addon 中的方法，用于处理 `log` 相关逻辑。
        """
        assert isinstance(level, int)
        logger.log(level=level, msg=f"[replay] {message}")

    async def handle_hook(self, hook: commands.StartHook) -> None:
        """
        处理重放过程中产生的生命周期 hook。

        这里仍交给 addon manager 分发，因此脚本和内置 addon 会看到一次正常的
        HTTP 请求/响应流程；响应或错误 hook 到达后关闭连接并标记本次重放完成。
        """
        (data,) = hook.args()
        await ctx.master.addons.handle_lifecycle(hook)
        if isinstance(data, flow.Flow):
            await data.wait_for_resume()
        if isinstance(hook, (layers.http.HttpResponseHook, layers.http.HttpErrorHook)):
            if self.transports:
                # close server connections
                for x in self.transports.values():
                    if x.handler:
                        x.handler.cancel()
                await asyncio.wait(
                    [x.handler for x in self.transports.values() if x.handler]
                )
            # signal completion
            self.done.set()


class ClientPlayback:
    """
    实现 `clientplayback` addon 的回放控制逻辑。
    """
    playback_task: asyncio.Task | None = None
    inflight: http.HTTPFlow | None
    queue: asyncio.Queue
    options: Options
    replay_tasks: set[asyncio.Task]

    def __init__(self):
        """
        初始化对象状态。
        """
        self.queue = asyncio.Queue()
        self.inflight = None
        self.task = None
        self.replay_tasks = set()

    def running(self):
        """
        `running` 事件：mitmproxy 启动完成后触发，创建后台重放消费者任务。
        """
        self.options = ctx.options
        self.playback_task = asyncio_utils.create_task(
            self.playback(),
            name="client playback",
            keep_ref=False,
        )

    async def done(self):
        """
        `done` 事件：mitmproxy 关闭时触发，取消后台重放任务。
        """
        if self.playback_task:
            self.playback_task.cancel()
            try:
                await self.playback_task
            except asyncio.CancelledError:
                pass

    async def playback(self):
        """
        后台队列消费者：逐条或无限并发执行重放请求。
        """
        while True:
            self.inflight = await self.queue.get()
            try:
                assert self.inflight
                h = ReplayHandler(self.inflight, self.options)
                if ctx.options.client_replay_concurrency == -1:
                    t = asyncio_utils.create_task(
                        h.replay(),
                        name="client playback awaiting response",
                        keep_ref=False,
                    )
                    # keep a reference so this is not garbage collected
                    self.replay_tasks.add(t)
                    t.add_done_callback(self.replay_tasks.remove)
                else:
                    await h.replay()
            except Exception:
                logger.exception(f"Client replay has crashed!")
            self.queue.task_done()
            self.inflight = None

    def check(self, f: flow.Flow) -> str | None:
        """
        根据过滤器或当前配置判断 flow 是否匹配。
        """
        if f.live or f == self.inflight:
            return "Can't replay live flow."
        if f.intercepted:
            return "Can't replay intercepted flow."
        if isinstance(f, http.HTTPFlow):
            if not f.request:
                return "Can't replay flow with missing request."
            if f.request.raw_content is None:
                return "Can't replay flow with missing content."
            if f.websocket is not None:
                return "Can't replay WebSocket flows."
        else:
            return "Can only replay HTTP flows."
        return None

    def load(self, loader):
        """
        addon 加载事件：注册客户端重放文件和并发选项。
        """
        loader.add_option(
            "client_replay",
            Sequence[str],
            [],
            "Replay client requests from a saved file.",
        )
        loader.add_option(
            "client_replay_concurrency",
            int,
            1,
            "Concurrency limit on in-flight client replay requests. Currently the only valid values are 1 and -1 (no limit).",
        )

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        `client_replay` 会在配置阶段读取 dump 文件并把可重放 flow 加入队列。
        """
        if "client_replay" in updated and ctx.options.client_replay:
            try:
                flows = io.read_flows_from_paths(ctx.options.client_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.start_replay(flows)

        if "client_replay_concurrency" in updated:
            if ctx.options.client_replay_concurrency not in [-1, 1]:
                raise exceptions.OptionsError(
                    "Currently the only valid client_replay_concurrency values are -1 and 1."
                )

    @command.command("replay.client.count")
    def count(self) -> int:
        """
        Approximate number of flows queued for replay.
        
        中文说明：命令触发点是 `replay.client.count`，返回队列长度加正在执行的
        一条 flow。
        """
        return self.queue.qsize() + int(bool(self.inflight))

    @command.command("replay.client.stop")
    def stop_replay(self) -> None:
        """
        Clear the replay queue.
        
        中文说明：命令触发点是 `replay.client.stop`。清空等待队列，并把未执行
        flow 恢复到重放前状态。
        """
        updated = []
        while True:
            try:
                f = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self.queue.task_done()
                f.revert()
                updated.append(f)

        ctx.master.addons.trigger(UpdateHook(updated))
        logger.log(ALERT, "Client replay queue cleared.")

    @command.command("replay.client")
    def start_replay(self, flows: Sequence[flow.Flow]) -> None:
        """
        Add flows to the replay queue, skipping flows that can't be replayed.
        
        中文说明：命令触发点是 `replay.client`。将选中 HTTP flow 备份、标记为
        request replay、清空旧 response/error 后加入后台队列。
        """
        updated: list[http.HTTPFlow] = []
        for f in flows:
            err = self.check(f)
            if err:
                logger.warning(err)
                continue

            http_flow = cast(http.HTTPFlow, f)

            # Prepare the flow for replay
            http_flow.backup()
            http_flow.is_replay = "request"
            http_flow.response = None
            http_flow.error = None
            self.queue.put_nowait(http_flow)
            updated.append(http_flow)
        ctx.master.addons.trigger(UpdateHook(updated))

    @command.command("replay.client.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
        Load flows from file, and add them to the replay queue.
        
        中文说明：命令触发点是 `replay.client.file`，从 dump 文件读取 flow 后
        复用 `start_replay()` 入队。
        """
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.start_replay(flows)
