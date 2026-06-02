"""
`mitmproxy.addons.core` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    `core` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        `core` addon 中的方法，用于处理 `flow set options` 相关逻辑。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
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
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        return ["gzip", "deflate", "br", "zstd"]

    @command.command("options.load")
    def options_load(self, path: mitmproxy.types.Path) -> None:
        """
        Load options from a file.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        try:
            optmanager.load_paths(ctx.options, path)
        except (OSError, exceptions.OptionsError) as e:
            raise exceptions.CommandError("Could not load options - %s" % e) from e

    @command.command("options.save")
    def options_save(self, path: mitmproxy.types.Path) -> None:
        """
        Save options to a file.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        try:
            optmanager.save(ctx.options, path)
        except OSError as e:
            raise exceptions.CommandError("Could not save options - %s" % e) from e

    @command.command("options.reset")
    def options_reset(self) -> None:
        """
        Reset all options to defaults.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        ctx.options.reset()

    @command.command("options.reset.one")
    def options_reset_one(self, name: str) -> None:
        """
        Reset one option to its default value.
        
        中文说明：该函数负责上方英文说明所描述的操作，通常作为命令、hook 或内部辅助逻辑被调用。
        """
        if name not in ctx.options:
            raise exceptions.CommandError("No such option: %s" % name)
        setattr(
            ctx.options,
            name,
            ctx.options.default(name),
        )
