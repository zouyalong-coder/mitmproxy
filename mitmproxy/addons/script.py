"""
加载、热重载并运行用户 addon 脚本的内置 addon。

触发点：
- `Script.running/done`：单个脚本 addon 的运行期初始化与收尾。
- `Script.watcher`：后台轮询脚本文件修改时间并热重载。
- `ScriptLoader.load/configure/running`：注册 `scripts` 选项并按配置管理脚本列表。
- `script.run` 命令：对指定 flows 临时运行一个脚本并模拟生命周期事件。
"""

import asyncio
import importlib.machinery
import importlib.util
import logging
import os
import sys
import types
from collections.abc import Sequence

import mitmproxy.types as mtypes
from mitmproxy import addonmanager
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import eventsequence
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


def load_script(path: str) -> types.ModuleType | None:
    """
    加载并执行用户脚本文件，返回脚本命名空间。
    """
    fullname = "__mitmproxy_script__.{}".format(
        os.path.splitext(os.path.basename(path))[0]
    )
    # the fullname is not unique among scripts, so if there already is an existing script with said
    # fullname, remove it.
    sys.modules.pop(fullname, None)
    oldpath = sys.path
    sys.path.insert(0, os.path.dirname(path))

    try:
        loader = importlib.machinery.SourceFileLoader(fullname, path)
        spec = importlib.util.spec_from_loader(fullname, loader=loader)
        assert spec
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        if not getattr(m, "name", None):
            m.name = path  # type: ignore
        return m
    except ImportError as e:
        if getattr(sys, "frozen", False):
            e.msg += (
                f".\n"
                f"Note that mitmproxy's binaries include their own Python environment. "
                f"If your addon requires the installation of additional dependencies, "
                f"please install mitmproxy from PyPI "
                f"(https://docs.mitmproxy.org/stable/overview-installation/#installation-from-the-python-package-index-pypi)."
            )
        script_error_handler(path, e)
        return None
    except Exception as e:
        script_error_handler(path, e)
        return None
    finally:
        sys.path[:] = oldpath


def script_error_handler(path: str, exc: Exception) -> None:
    """
    Log errors during script loading.
    
    中文说明：脚本加载失败时裁剪框架内部 traceback，只保留对用户脚本有帮助的
    部分并写入日志。
    """
    tback = exc.__traceback__
    tback = addonmanager.cut_traceback(
        tback, "invoke_addon_sync"
    )  # we're calling configure() on load
    tback = addonmanager.cut_traceback(
        tback, "_call_with_frames_removed"
    )  # module execution from importlib
    logger.error(f"error in script {path}", exc_info=(type(exc), exc, tback))


ReloadInterval = 1


class Script:
    """
    An addon that manages a single script.
    
    中文说明：每个 `Script` 实例管理一个用户脚本文件，把脚本模块注册为真正
    的 addon，并在文件变化时重新加载。
    """

    def __init__(self, path: str, reload: bool) -> None:
        """
        初始化脚本路径、当前模块命名空间和可选热重载任务。
        """
        self.name = "scriptmanager:" + path
        self.path = path
        self.fullpath = os.path.expanduser(path.strip("'\" "))
        self.ns: types.ModuleType | None = None
        self.is_running = False

        if not os.path.isfile(self.fullpath):
            raise exceptions.OptionsError(f"No such script: {self.fullpath}")

        self.reloadtask = None
        if reload:
            self.reloadtask = asyncio_utils.create_task(
                self.watcher(),
                name=f"script watcher for {path}",
                keep_ref=False,
            )
        else:
            self.loadscript()

    def running(self):
        """
        `running` 事件：mitmproxy 启动完成后触发，并标记脚本管理器已进入运行态。
        """
        self.is_running = True

    def done(self):
        """
        `done` 事件：mitmproxy 关闭时触发，取消脚本热重载任务。
        """
        if self.reloadtask:
            self.reloadtask.cancel()

    @property
    def addons(self):
        """
        返回当前脚本模块作为子 addon，供 addon manager 分发 hook。
        """
        return [self.ns] if self.ns else []

    def loadscript(self):
        """
        加载或重载脚本文件，并把模块注册到 addon manager。

        重载时会先移除旧模块，再对新模块触发 configure；如果 mitmproxy 已经
        running，还会补发 running hook。
        """
        logger.info("Loading script %s" % self.path)
        if self.ns:
            ctx.master.addons.remove(self.ns)
        self.ns = None
        with addonmanager.safecall():
            ns = load_script(self.fullpath)
            ctx.master.addons.register(ns)
            self.ns = ns
        if self.ns:
            try:
                ctx.master.addons.invoke_addon_sync(
                    self.ns, hooks.ConfigureHook(ctx.options.keys())
                )
            except Exception as e:
                script_error_handler(self.fullpath, e)
            if self.is_running:
                # We're already running, so we call that on the addon now.
                ctx.master.addons.invoke_addon_sync(self.ns, hooks.RunningHook())

    async def watcher(self):
        # Script loading is terminally confused at the moment.
        # This here is a stopgap workaround to defer loading.
        """
        热重载 watcher：定期检查脚本 mtime，变化后重新加载。
        """
        await asyncio.sleep(0)
        last_mtime = 0.0
        while True:
            try:
                mtime = os.stat(self.fullpath).st_mtime
            except FileNotFoundError:
                logger.info("Removing script %s" % self.path)
                scripts = list(ctx.options.scripts)
                scripts.remove(self.path)
                ctx.options.update(scripts=scripts)
                return
            if mtime > last_mtime:
                self.loadscript()
                last_mtime = mtime
            await asyncio.sleep(ReloadInterval)


class ScriptLoader:
    """
    An addon that manages loading scripts from options.
    
    中文说明：负责根据 `scripts` 选项创建、排序、移除多个 `Script` 子 addon。
    """

    def __init__(self):
        """
        初始化脚本列表和运行态标记。
        """
        self.is_running = False
        self.addons = []

    def load(self, loader):
        """
        addon 加载事件：注册 `scripts` 配置项。
        """
        loader.add_option("scripts", Sequence[str], [], "Execute a script.")

    def running(self):
        """
        `running` 事件：mitmproxy 启动完成后触发。
        """
        self.is_running = True

    @command.command("script.run")
    def script_run(self, flows: Sequence[flow.Flow], path: mtypes.Path) -> None:
        """
        Run a script on the specified flows. The script is configured with
        the current options and all lifecycle events for each flow are
        simulated. Note that the load event is not invoked.
        
        中文说明：命令触发点是 `script.run`。它不会触发脚本的 load 事件，但会
        对指定 flows 依次模拟 request/response/error 等生命周期事件。
        """
        if not os.path.isfile(path):
            logger.error("No such script: %s" % path)
            return
        mod = load_script(path)
        if mod:
            with addonmanager.safecall():
                ctx.master.addons.invoke_addon_sync(
                    mod,
                    hooks.ConfigureHook(ctx.options.keys()),
                )
                ctx.master.addons.invoke_addon_sync(mod, hooks.RunningHook())
                for f in flows:
                    for evt in eventsequence.iterate(f):
                        ctx.master.addons.invoke_addon_sync(mod, evt)

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "scripts" in updated:
            for s in ctx.options.scripts:
                if ctx.options.scripts.count(s) > 1:
                    raise exceptions.OptionsError("Duplicate script")

            for a in self.addons[:]:
                if a.path not in ctx.options.scripts:
                    logger.info("Un-loading script: %s" % a.path)
                    ctx.master.addons.remove(a)
                    self.addons.remove(a)

            # The machinations below are to ensure that:
            #   - Scripts remain in the same order
            #   - Scripts are not initialized un-necessarily. If only a
            #   script's order in the script list has changed, it is just
            #   moved.

            current = {}
            for a in self.addons:
                current[a.path] = a

            ordered = []
            newscripts = []
            for s in ctx.options.scripts:
                if s in current:
                    ordered.append(current[s])
                else:
                    sc = Script(s, True)
                    ordered.append(sc)
                    newscripts.append(sc)

            self.addons = ordered

            for s in newscripts:
                ctx.master.addons.register(s)
                if self.is_running:
                    # If we're already running, we configure and tell the addon
                    # we're up and running.
                    ctx.master.addons.invoke_addon_sync(s, hooks.RunningHook())
