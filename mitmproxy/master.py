import asyncio
import logging

from . import ctx as mitmproxy_ctx
from .addons import termlog
from .proxy.mode_specs import ReverseMode
from .utils import asyncio_utils
from mitmproxy import addonmanager
from mitmproxy import command
from mitmproxy import eventsequence
from mitmproxy import hooks
from mitmproxy import http
from mitmproxy import log
from mitmproxy import options

logger = logging.getLogger(__name__)


class Master:
    """
    The master handles mitmproxy's main event loop.

    Master 负责 mitmproxy 的主生命周期和事件循环调度。它持有全局配置、
    命令管理器和 addon 管理器，并通过 asyncio event loop 协调代理服务、
    addon hook、信号处理和关闭流程。
    使用 event loop 的主要好处是：大量网络连接可以在单线程内非阻塞并发处理，
    同时 addon hook、退出信号、后台任务和状态变更都能回到同一个调度模型里，
    时序更可控，也更适合 mitmproxy 这种 I/O 密集型代理程序。
    """

    event_loop: asyncio.AbstractEventLoop
    _termlog_addon: termlog.TermLog | None = None

    def __init__(
        self,
        opts: options.Options | None,
        event_loop: asyncio.AbstractEventLoop | None = None,
        with_termlog: bool = False,
    ):
        """
        初始化 mitmproxy 的主控制器。

        `event_loop` 是 mitmproxy 所有异步任务的调度中心。代理连接、server
        启动、addon 中创建的后台任务，以及 shutdown 信号最终都会回到这个
        loop 上执行。使用 event loop 的好处是：大量网络连接可以在单线程内
        非阻塞并发处理，同时又能保证状态变更和 hook 调用按明确的时序进入
        主线程上下文。
        """
        self.options: options.Options = opts or options.Options()
        self.commands = command.CommandManager(self)
        self.addons = addonmanager.AddonManager(self)

        if with_termlog:
            self._termlog_addon = termlog.TermLog()
            self.addons.add(self._termlog_addon)

        self.log = log.Log(self)  # deprecated, do not use.
        self._legacy_log_events = log.LegacyLogEvents(self)
        self._legacy_log_events.install()

        # We expect an active event loop here already because some addons
        # may want to spawn tasks during the initial configuration phase,
        # which happens before run().
        # 这里要求已经存在活动 event loop，因为部分 addon 会在初始配置阶段
        # 就创建异步任务。提前保存 loop 可以让后续 shutdown 或跨线程回调都
        # 投递回同一个调度中心。
        self.event_loop = event_loop or asyncio.get_running_loop()
        self.should_exit = asyncio.Event()
        # ctx 是对用户 addon 暴露的全局快捷入口。这里把当前 Master、日志和
        # options 挂上去，让脚本可以通过 mitmproxy.ctx 访问运行时环境。
        mitmproxy_ctx.master = self
        mitmproxy_ctx.log = self.log  # deprecated, do not use.
        mitmproxy_ctx.options = self.options

    async def run(self) -> None:
        """
        运行 mitmproxy 主生命周期。

        流程是：安装 asyncio 异常处理器，启动代理服务器，触发 running hook，
        然后等待 `should_exit`。整个过程运行在 event loop 中，因此服务器
        启动、连接处理、addon hook 和退出等待都可以以非阻塞任务形式协作。
        """
        with (
            asyncio_utils.install_exception_handler(self._asyncio_exception_handler),
            asyncio_utils.set_eager_task_factory(),
        ):
            self.should_exit.clear()

            # Can we exit before even bringing up servers?
            # 在真正启动监听前先检查启动期错误，这样配置错误可以尽早结束。
            if ec := self.addons.get("errorcheck"):
                await ec.shutdown_if_errored()
            if ps := self.addons.get("proxyserver"):
                # This may block for some proxy modes, so we also monitor should_exit.
                # 某些代理模式的启动可能等待外部资源。这里并行等待
                # setup_servers 和 should_exit，允许用户在启动过程中也能中断。
                await asyncio.wait(
                    [
                        asyncio_utils.create_task(
                            ps.setup_servers(), name="setup_servers", keep_ref=False
                        ),
                        asyncio_utils.create_task(
                            self.should_exit.wait(), name="should_exit", keep_ref=False
                        ),
                    ],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if self.should_exit.is_set():
                    return
                # Did bringing up servers fail?
                # 服务器启动后再检查一次错误，确保绑定端口失败等问题能终止启动。
                if ec := self.addons.get("errorcheck"):
                    await ec.shutdown_if_errored()

            try:
                await self.running()
                # Any errors in the final part of startup?
                # running hook 也可能由 addon 抛出或记录错误，完成后做最后检查。
                if ec := self.addons.get("errorcheck"):
                    await ec.shutdown_if_errored()
                    ec.finish()

                # 主循环本身就是等待退出事件。代理连接处理任务由 proxyserver
                # 及其连接 handler 在同一个 event loop 中调度。
                await self.should_exit.wait()
            finally:
                # if running() was called, we also always want to call done().
                # .wait might be cancelled (e.g. by sys.exit), so  this needs to be in a finally block.
                # 只要进入 running 阶段，就必须在 finally 中触发 done，保证 addon
                # 有机会释放资源，即使等待退出时被取消也是如此。
                await self.done()

    def shutdown(self):
        """
        Shut down the proxy. This method is thread-safe.

        关闭代理。这个方法是线程安全的。

        通过 `call_soon_threadsafe` 把退出事件投递到 Master 所属 event loop，
        避免从信号处理器或其他线程直接修改 asyncio 状态。
        """
        # We may add an exception argument here.
        self.event_loop.call_soon_threadsafe(self.should_exit.set)

    async def running(self) -> None:
        """
        触发 mitmproxy 已完成启动的生命周期 hook。
        """
        await self.addons.trigger_event(hooks.RunningHook())

    async def done(self) -> None:
        """
        触发关闭生命周期 hook，并清理 Master 自己安装的日志组件。
        """
        await self.addons.trigger_event(hooks.DoneHook())
        self._legacy_log_events.uninstall()
        if self._termlog_addon is not None:
            self._termlog_addon.uninstall()

    def _asyncio_exception_handler(self, loop, context) -> None:
        """
        统一处理 event loop 中未被任务捕获的异常。

        asyncio 后台任务如果没有被 await，异常容易被遗漏。把异常处理器安装
        到 event loop 后，mitmproxy 可以集中记录这些错误，避免后台连接任务
        静默失败。
        """
        try:
            exc: Exception = context["exception"]
        except KeyError:
            logger.error(f"Unhandled asyncio error: {context}")
        else:
            if isinstance(exc, OSError) and exc.errno == 10038:
                return  # suppress https://bugs.python.org/issue43253
            logger.error(
                "Unhandled error in task.",
                exc_info=(type(exc), exc, exc.__traceback__),
            )

    async def load_flow(self, f):
        """
        Loads a flow

        加载一个已有 flow，并按正常生命周期重新触发对应 hook。
        """

        if (
            isinstance(f, http.HTTPFlow)
            and len(self.options.mode) == 1
            and self.options.mode[0].startswith("reverse:")
        ):
            # When we load flows in reverse proxy mode, we adjust the target host to
            # the reverse proxy destination for all flows we load. This makes it very
            # easy to replay saved flows against a different host.
            # We may change this in the future so that clientplayback always replays to the first mode.
            # 反向代理模式下加载历史 flow 时，把目标地址改成当前 reverse 目标。
            # 这样同一份保存的请求可以方便地重放到新的后端服务上。
            mode = ReverseMode.parse(self.options.mode[0])
            assert isinstance(mode, ReverseMode)
            f.request.host, f.request.port, *_ = mode.address
            f.request.scheme = mode.scheme

        # 将 flow 拆成 request/response/websocket/tcp 等生命周期事件，交给
        # AddonManager 分发。这样“加载历史 flow”和“实时收到 flow”对 addon
        # 来说走的是同一套 hook 入口。
        for e in eventsequence.iterate(f):
            await self.addons.handle_lifecycle(e)
