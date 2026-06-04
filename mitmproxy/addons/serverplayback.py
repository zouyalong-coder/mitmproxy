"""
服务端回放 addon：用历史响应匹配当前请求，避免访问真实上游。

触发点：
- `load`：注册 server replay 相关选项。
- `configure`：从配置文件加载回放 flow，或在匹配规则变化时重建哈希表。
- `replay.server*` 命令：加载、追加、停止或统计回放响应。
- `request`：HTTP 请求发往上游前触发，命中历史响应时直接设置 `flow.response`。
"""

import hashlib
import logging
import urllib
from collections.abc import Hashable
from collections.abc import Sequence
from typing import Any

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy import http
from mitmproxy import io

logger = logging.getLogger(__name__)

HASH_OPTIONS = [
    "server_replay_ignore_content",
    "server_replay_ignore_host",
    "server_replay_ignore_params",
    "server_replay_ignore_payload_params",
    "server_replay_ignore_port",
    "server_replay_use_headers",
]


class ServerPlayback:
    """
    实现服务端响应回放的匹配和短路响应逻辑。

    与 client replay 不同，它不会重新发送请求，而是在当前请求命中历史记录时
    复制历史响应并直接返回给客户端。
    """
    flowmap: dict[Hashable, list[http.HTTPFlow]]
    configured: bool

    def __init__(self):
        """
        初始化请求哈希到候选历史 flow 的映射。
        """
        self.flowmap = {}
        self.configured = False

    def load(self, loader):
        """
        addon 加载事件：注册服务端回放匹配、复用和额外请求处理选项。
        """
        loader.add_option(
            "server_replay_kill_extra",
            bool,
            False,
            "Kill extra requests during replay (for which no replayable response was found)."
            "[Deprecated, prefer to use server_replay_extra='kill']",
        )
        loader.add_option(
            "server_replay_extra",
            str,
            "forward",
            "Behaviour for extra requests during replay for which no replayable response was found. "
            "Setting a numeric string value will return an empty HTTP response with the respective status code.",
            choices=["forward", "kill", "204", "400", "404", "500"],
        )
        loader.add_option(
            "server_replay_reuse",
            bool,
            False,
            """
            Don't remove flows from server replay state after use. This makes it
            possible to replay same response multiple times.
            """,
        )
        loader.add_option(
            "server_replay_nopop",
            bool,
            False,
            """
            Deprecated alias for `server_replay_reuse`.
            """,
        )
        loader.add_option(
            "server_replay_refresh",
            bool,
            True,
            """
            Refresh server replay responses by adjusting date, expires and
            last-modified headers, as well as adjusting cookie expiration.
            """,
        )
        loader.add_option(
            "server_replay_use_headers",
            Sequence[str],
            [],
            """
            Request headers that need to match while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay",
            Sequence[str],
            [],
            "Replay server responses from a saved file.",
        )
        loader.add_option(
            "server_replay_ignore_content",
            bool,
            False,
            "Ignore request content while searching for a saved flow to replay.",
        )
        loader.add_option(
            "server_replay_ignore_params",
            Sequence[str],
            [],
            """
            Request parameters to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_payload_params",
            Sequence[str],
            [],
            """
            Request payload parameters (application/x-www-form-urlencoded or
            multipart/form-data) to be ignored while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_host",
            bool,
            False,
            """
            Ignore request destination host while searching for a saved flow
            to replay.
            """,
        )
        loader.add_option(
            "server_replay_ignore_port",
            bool,
            False,
            """
            Ignore request destination port while searching for a saved flow
            to replay.
            """,
        )

    @command.command("replay.server")
    def load_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Replay server responses from flows.
        
        中文说明：命令触发点是 `replay.server`。清空当前回放库，再载入传入
        flows 的响应。
        """
        self.flowmap = {}
        self.add_flows(flows)

    @command.command("replay.server.add")
    def add_flows(self, flows: Sequence[flow.Flow]) -> None:
        """
        Add responses from flows to server replay list.
        
        中文说明：命令触发点是 `replay.server.add`。把传入 HTTP flow 按当前
        哈希规则加入回放库。
        """
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                lst = self.flowmap.setdefault(self._hash(f), [])
                lst.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
        `replay.server.file` 命令：从 dump 文件读取 flow 并替换当前回放库。
        """
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.server.stop")
    def clear(self) -> None:
        """
        Stop server replay.
        
        中文说明：命令触发点是 `replay.server.stop`，清空所有可回放响应。
        """
        self.flowmap = {}
        ctx.master.addons.trigger(hooks.UpdateHook([]))

    @command.command("replay.server.count")
    def count(self) -> int:
        """
        `replay.server.count` 命令：返回当前回放库中剩余响应数量。
        """
        return sum(len(i) for i in self.flowmap.values())

    def _hash(self, flow: http.HTTPFlow) -> Hashable:
        """
        Calculates a loose hash of the flow request.
        
        中文说明：根据当前 server_replay_* 选项构造宽松匹配键。可忽略 host、
        port、query 参数、body 或指定 header，从而控制“当前请求”和“历史请求”
        怎样才算同一个请求。
        """
        r = flow.request
        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

        key: list[Any] = [str(r.scheme), str(r.method), str(path)]
        if not ctx.options.server_replay_ignore_content:
            if ctx.options.server_replay_ignore_payload_params and r.multipart_form:
                key.extend(
                    (k, v)
                    for k, v in r.multipart_form.items(multi=True)
                    if k.decode(errors="replace")
                    not in ctx.options.server_replay_ignore_payload_params
                )
            elif ctx.options.server_replay_ignore_payload_params and r.urlencoded_form:
                key.extend(
                    (k, v)
                    for k, v in r.urlencoded_form.items(multi=True)
                    if k not in ctx.options.server_replay_ignore_payload_params
                )
            else:
                key.append(str(r.raw_content))

        if not ctx.options.server_replay_ignore_host:
            key.append(r.pretty_host)
        if not ctx.options.server_replay_ignore_port:
            key.append(r.port)

        filtered = []
        ignore_params = ctx.options.server_replay_ignore_params or []
        for p in queriesArray:
            if p[0] not in ignore_params:
                filtered.append(p)
        for p in filtered:
            key.append(p[0])
            key.append(p[1])

        if ctx.options.server_replay_use_headers:
            headers = []
            for i in ctx.options.server_replay_use_headers:
                v = r.headers.get(i)
                headers.append((i, v))
            key.append(headers)
        return hashlib.sha256(repr(key).encode("utf8", "surrogateescape")).digest()

    def next_flow(self, flow: http.HTTPFlow) -> http.HTTPFlow | None:
        """
        Returns the next flow object, or None if no matching flow was
        found.
        
        中文说明：按当前请求哈希查找可用历史 flow。默认命中后弹出一条，开启
        `server_replay_reuse` 时则保留以便重复使用。
        """
        hash = self._hash(flow)
        if hash in self.flowmap:
            if ctx.options.server_replay_reuse or ctx.options.server_replay_nopop:
                return next(
                    (flow for flow in self.flowmap[hash] if flow.response), None
                )
            else:
                ret = self.flowmap[hash].pop(0)
                while not ret.response:
                    if self.flowmap[hash]:
                        ret = self.flowmap[hash].pop(0)
                    else:
                        del self.flowmap[hash]
                        return None
                if not self.flowmap[hash]:
                    del self.flowmap[hash]
                return ret
        else:
            return None

    def configure(self, updated):
        """
        `configure` 事件：选项变化后触发。

        首次配置 `server_replay` 时加载文件；影响哈希规则的选项变化时重建
        `flowmap`，确保之后的 request hook 使用新匹配规则。
        """
        if ctx.options.server_replay_kill_extra:
            logger.warning(
                "server_replay_kill_extra has been deprecated, "
                "please update your config to use server_replay_extra='kill'."
            )
        if ctx.options.server_replay_nopop:  # pragma: no cover
            logger.error(
                "server_replay_nopop has been renamed to server_replay_reuse, please update your config."
            )
        if not self.configured and ctx.options.server_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.server_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)
        if any(option in updated for option in HASH_OPTIONS):
            self.recompute_hashes()

    def recompute_hashes(self) -> None:
        """
        Rebuild flowmap if the hashing method has changed during execution,
        see https://github.com/mitmproxy/mitmproxy/issues/4506
        
        中文说明：哈希规则变化后，必须用新规则重新给已加载 flow 分组。
        """
        flows = [flow for lst in self.flowmap.values() for flow in lst]
        self.load_flows(flows)

    def request(self, f: http.HTTPFlow) -> None:
        """
        HTTP `request` 事件：请求发往上游前触发。

        命中历史响应时复制 response 并设置 `is_replay="response"`；未命中时按
        `server_replay_extra` 选择转发、kill 或返回指定状态码。
        """
        if self.flowmap:
            rflow = self.next_flow(f)
            if rflow:
                assert rflow.response
                response = rflow.response.copy()
                if ctx.options.server_replay_refresh:
                    response.refresh()
                f.response = response
                f.is_replay = "response"
            elif (
                ctx.options.server_replay_kill_extra
                or ctx.options.server_replay_extra == "kill"
            ):
                logging.warning(
                    "server_playback: killed non-replay request {}".format(
                        f.request.url
                    )
                )
                f.kill()
            elif ctx.options.server_replay_extra != "forward":
                logging.warning(
                    "server_playback: returned {} non-replay request {}".format(
                        ctx.options.server_replay_extra, f.request.url
                    )
                )
                f.response = http.Response.make(int(ctx.options.server_replay_extra))
                f.is_replay = "response"
