"""
mitmproxy 的核心命令 addon。

触发点：
- `configure`：选项变化时做跨选项校验。
- `set`、`flow.*`、`options.*` 命令：由控制台、Web UI、快捷键或其他 addon 调用。
- 本模块基本不监听网络生命周期事件，主要负责修改 flow/option 后触发 `UpdateHook`。
"""

import logging
import os
from collections.abc import Sequence

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy import optmanager
from mitmproxy.log import ALERT
from mitmproxy.net.http import status_codes
from mitmproxy.utils import emoji

logger = logging.getLogger(__name__)

CONF_DIR = "~/.mitmproxy"
LISTEN_PORT = 8080


class Core:
    """
    提供通用 flow 操作、编码/解码和选项读写命令。
    """

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        这里校验会影响全局行为的配置组合，例如客户端证书路径是否存在。
        """
        opts = ctx.options
        if opts.add_upstream_certs_to_client_chain and not opts.upstream_cert:
            raise exceptions.OptionsError(
                "add_upstream_certs_to_client_chain requires the upstream_cert option to be enabled."
            )
        if "client_certs" in updated:
            if opts.client_certs:
                client_certs = os.path.expanduser(opts.client_certs)
                if not os.path.exists(client_certs):
                    raise exceptions.OptionsError(
                        f"Client certificate path does not exist: {opts.client_certs}"
                    )

    @command.command("set")
    def set(self, option: str, *value: str) -> None:
        """
        Set an option. When the value is omitted, booleans are set to true,
        strings and integers are set to None (if permitted), and sequences
        are emptied. Boolean values can be true, false or toggle.
        Multiple values are concatenated with a single space.
        
        中文说明：命令触发点是 `set`，最终调用 `ctx.options.set()` 并复用选项
        系统的类型转换和回滚机制。
        """
        if value:
            specs = [f"{option}={v}" for v in value]
        else:
            specs = [option]
        try:
            ctx.options.set(*specs)
        except exceptions.OptionsError as e:
            raise exceptions.CommandError(e) from e

    @command.command("flow.resume")
    def resume(self, flows: Sequence[flow.Flow]) -> None:
        """
        Resume flows if they are intercepted.
        
        中文说明：命令触发点是 `flow.resume`，恢复被 intercept 暂停的 flow。
        """
        intercepted = [i for i in flows if i.intercepted]
        for f in intercepted:
            f.resume()
        ctx.master.addons.trigger(hooks.UpdateHook(intercepted))

    # FIXME: this will become view.mark later
    @command.command("flow.mark")
    def mark(self, flows: Sequence[flow.Flow], marker: mitmproxy.types.Marker) -> None:
        """
        Mark flows.
        
        中文说明：命令触发点是 `flow.mark`，设置用户标记后触发 UpdateHook。
        """
        updated = []
        if not (marker == "" or marker in emoji.emoji):
            raise exceptions.CommandError(f"invalid marker value")

        for i in flows:
            i.marked = marker
            updated.append(i)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    # FIXME: this will become view.mark.toggle later
    @command.command("flow.mark.toggle")
    def mark_toggle(self, flows: Sequence[flow.Flow]) -> None:
        """
        Toggle mark for flows.
        
        中文说明：命令触发点是 `flow.mark.toggle`，在默认标记和无标记之间切换。
        """
        for i in flows:
            if i.marked:
                i.marked = ""
            else:
                i.marked = ":default:"
        ctx.master.addons.trigger(hooks.UpdateHook(flows))

    @command.command("flow.kill")
    def kill(self, flows: Sequence[flow.Flow]) -> None:
        """
        Kill running flows.
        
        中文说明：命令触发点是 `flow.kill`，只会 kill 当前仍可终止的 live flow。
        """
        updated = []
        for f in flows:
            if f.killable:
                f.kill()
                updated.append(f)
        logger.log(ALERT, "Killed %s flows." % len(updated))
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    # FIXME: this will become view.revert later
    @command.command("flow.revert")
    def revert(self, flows: Sequence[flow.Flow]) -> None:
        """
        Revert flow changes.
        
        中文说明：命令触发点是 `flow.revert`，恢复此前 `backup()` 保存的状态。
        """
        updated = []
        for f in flows:
            if f.modified():
                f.revert()
                updated.append(f)
        logger.log(ALERT, "Reverted %s flows." % len(updated))
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    @command.command("flow.set.options")
    def flow_set_options(self) -> Sequence[str]:
        """
        `flow.set.options` 命令：返回 `flow.set` 支持的字段名，用于补全。
        """
        return [
            "host",
            "status_code",
            "method",
            "path",
            "url",
            "reason",
        ]

    @command.command("flow.set")
    @command.argument("attr", type=mitmproxy.types.Choice("flow.set.options"))
    def flow_set(self, flows: Sequence[flow.Flow], attr: str, value: str) -> None:
        """
        Quickly set a number of common values on flows.
        
        中文说明：命令触发点是 `flow.set`，用于快速修改常见请求/响应字段。
        """
        val: int | str = value
        if attr == "status_code":
            try:
                val = int(val)  # type: ignore
            except ValueError as v:
                raise exceptions.CommandError(
                    "Status code is not an integer: %s" % val
                ) from v

        updated = []
        for f in flows:
            req = getattr(f, "request", None)
            rupdate = True
            if req:
                if attr == "method":
                    req.method = val
                elif attr == "host":
                    req.host = val
                elif attr == "path":
                    req.path = val
                elif attr == "url":
                    try:
                        req.url = val
                    except ValueError as e:
                        raise exceptions.CommandError(
                            f"URL {val!r} is invalid: {e}"
                        ) from e
                else:
                    self.rupdate = False

            resp = getattr(f, "response", None)
            supdate = True
            if resp:
                if attr == "status_code":
                    resp.status_code = val
                    if val in status_codes.RESPONSES:
                        resp.reason = status_codes.RESPONSES[val]  # type: ignore
                elif attr == "reason":
                    resp.reason = val
                else:
                    supdate = False

            if rupdate or supdate:
                updated.append(f)

        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        logger.log(ALERT, f"Set {attr} on  {len(updated)} flows.")

    @command.command("flow.decode")
    def decode(self, flows: Sequence[flow.Flow], part: str) -> None:
        """
        Decode flows.
        
        中文说明：命令触发点是 `flow.decode`，对 request/response 等 part 调用
        `decode()`。
        """
        updated = []
        for f in flows:
            p = getattr(f, part, None)
            if p:
                f.backup()
                p.decode()
                updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        logger.log(ALERT, "Decoded %s flows." % len(updated))

    @command.command("flow.encode.toggle")
    def encode_toggle(self, flows: Sequence[flow.Flow], part: str) -> None:
        """
        Toggle flow encoding on and off, using deflate for encoding.
        
        中文说明：命令触发点是 `flow.encode.toggle`，在 identity 和 deflate 之间
        切换。
        """
        updated = []
        for f in flows:
            p = getattr(f, part, None)
            if p:
                f.backup()
                current_enc = p.headers.get("content-encoding", "identity")
                if current_enc == "identity":
                    p.encode("deflate")
                else:
                    p.decode()
                updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        logger.log(ALERT, "Toggled encoding on %s flows." % len(updated))

    @command.command("flow.encode")
    @command.argument("encoding", type=mitmproxy.types.Choice("flow.encode.options"))
    def encode(
        self,
        flows: Sequence[flow.Flow],
        part: str,
        encoding: str,
    ) -> None:
        """
        Encode flows with a specified encoding.
        
        中文说明：命令触发点是 `flow.encode`，仅在当前未编码时应用指定编码。
        """
        updated = []
        for f in flows:
            p = getattr(f, part, None)
            if p:
                current_enc = p.headers.get("content-encoding", "identity")
                if current_enc == "identity":
                    f.backup()
                    p.encode(encoding)
                    updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        logger.log(ALERT, "Encoded %s flows." % len(updated))

    @command.command("flow.encode.options")
    def encode_options(self) -> Sequence[str]:
        """
        The possible values for an encoding specification.
        
        中文说明：命令触发点是 `flow.encode.options`，用于命令参数补全。
        """
        return ["gzip", "deflate", "br", "zstd"]

    @command.command("options.load")
    def options_load(self, path: mitmproxy.types.Path) -> None:
        """
        Load options from a file.
        
        中文说明：命令触发点是 `options.load`，从 YAML 配置文件载入选项。
        """
        try:
            optmanager.load_paths(ctx.options, path)
        except (OSError, exceptions.OptionsError) as e:
            raise exceptions.CommandError("Could not load options - %s" % e) from e

    @command.command("options.save")
    def options_save(self, path: mitmproxy.types.Path) -> None:
        """
        Save options to a file.
        
        中文说明：命令触发点是 `options.save`，把当前选项写入文件。
        """
        try:
            optmanager.save(ctx.options, path)
        except OSError as e:
            raise exceptions.CommandError("Could not save options - %s" % e) from e

    @command.command("options.reset")
    def options_reset(self) -> None:
        """
        Reset all options to defaults.
        
        中文说明：命令触发点是 `options.reset`，恢复所有选项默认值。
        """
        ctx.options.reset()

    @command.command("options.reset.one")
    def options_reset_one(self, name: str) -> None:
        """
        Reset one option to its default value.
        
        中文说明：命令触发点是 `options.reset.one`，恢复单个选项默认值。
        """
        if name not in ctx.options:
            raise exceptions.CommandError("No such option: %s" % name)
        setattr(
            ctx.options,
            name,
            ctx.options.default(name),
        )
