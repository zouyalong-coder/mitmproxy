"""
This addon is responsible for starting/stopping the proxy server sockets/instances specified by the mode option.

中文说明：本模块负责真正启动、停止和管理代理监听 socket，以及维护 live
connection handler。它也是 TCP/UDP/WebSocket 注入命令的入口。

触发点：
- `load`：注册代理服务器、流式 body、连接策略等选项。
- `running`：标记代理服务器 addon 已进入运行态。
- `configure`：mode/server/connect_addr 等选项变化时校验并启动/停止监听实例。
- `setup_servers`：master 启动阶段调用，用于首次创建监听服务器。
- `inject.*` 命令：向 live flow 注入 WebSocket/TCP/UDP 消息。
- `server_connect`：即将连接上游服务器时触发，设置本地出站地址并防止自连。
"""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import logging
from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Optional

from wsproto.frame_protocol import Opcode

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import platform
from mitmproxy import tcp
from mitmproxy import udp
from mitmproxy import websocket
from mitmproxy.connection import Address
from mitmproxy.flow import Flow
from mitmproxy.proxy import events
from mitmproxy.proxy import mode_specs
from mitmproxy.proxy import server_hooks
from mitmproxy.proxy.layers.tcp import TcpMessageInjected
from mitmproxy.proxy.layers.udp import UdpMessageInjected
from mitmproxy.proxy.layers.websocket import WebSocketMessageInjected
from mitmproxy.proxy.mode_servers import ProxyConnectionHandler
from mitmproxy.proxy.mode_servers import ServerInstance
from mitmproxy.proxy.mode_servers import ServerManager
from mitmproxy.utils import asyncio_utils
from mitmproxy.utils import human
from mitmproxy.utils import signals

logger = logging.getLogger(__name__)


class Servers:
    """
    管理当前启用的代理服务实例集合。
    """
    def __init__(self, manager: ServerManager):
        """
        初始化服务实例表、更新锁和变更信号。
        """
        self.changed = signals.AsyncSignal(lambda: None)
        self._instances: dict[mode_specs.ProxyMode, ServerInstance] = dict()
        self._lock = asyncio.Lock()
        self._manager = manager

    @property
    def is_updating(self) -> bool:
        """
        返回当前是否正在启动/停止监听实例。
        """
        return self._lock.locked()

    async def update(self, modes: Iterable[mode_specs.ProxyMode]) -> bool:
        """
        按新的 mode 列表同步监听实例。

        新增 mode 会创建并启动 ServerInstance，移除的 mode 会停止；更新前后都会
        发送 changed 信号，让 UI 或其他组件刷新监听状态。
        """
        all_ok = True

        async with self._lock:
            new_instances: dict[mode_specs.ProxyMode, ServerInstance] = {}

            start_tasks = []
            if ctx.options.server:
                # Create missing modes and keep existing ones.
                for spec in modes:
                    if spec in self._instances:
                        instance = self._instances[spec]
                    else:
                        instance = ServerInstance.make(spec, self._manager)
                        start_tasks.append(instance.start())
                    new_instances[spec] = instance

            # Shutdown modes that have been removed from the list.
            stop_tasks = [
                s.stop()
                for spec, s in self._instances.items()
                if spec not in new_instances
            ]

            if not start_tasks and not stop_tasks:
                return (
                    True  # nothing to do, so we don't need to trigger `self.changed`.
                )

            self._instances = new_instances
            # Notify listeners about the new not-yet-started servers.
            await self.changed.send()

            # We first need to free ports before starting new servers.
            for ret in await asyncio.gather(*stop_tasks, return_exceptions=True):
                if ret:
                    all_ok = False
                    logger.error(str(ret))
            for ret in await asyncio.gather(*start_tasks, return_exceptions=True):
                if ret:
                    all_ok = False
                    logger.error(str(ret))

        await self.changed.send()
        return all_ok

    def __len__(self) -> int:
        """
        返回当前集合或视图中的元素数量。
        """
        return len(self._instances)

    def __iter__(self) -> Iterator[ServerInstance]:
        """
        迭代当前集合或视图中的元素。
        """
        return iter(self._instances.values())

    def __getitem__(self, mode: str | mode_specs.ProxyMode) -> ServerInstance:
        """
        按索引或键读取当前集合中的元素。
        """
        if isinstance(mode, str):
            mode = mode_specs.ProxyMode.parse(mode)
        return self._instances[mode]


class Proxyserver(ServerManager):
    """
    This addon runs the actual proxy server.
    
    中文说明：它继承 `ServerManager`，既负责监听实例的生命周期，也负责给代理
    核心提供连接注册、事件注入和上游连接参数。
    """

    connections: dict[tuple | str, ProxyConnectionHandler]
    servers: Servers

    is_running: bool
    _connect_addr: Address | None = None

    def __init__(self):
        """
        初始化 live connection 表、Servers 管理器和运行态标记。
        """
        self.connections = {}
        self.servers = Servers(self)
        self.is_running = False

    def __repr__(self):
        """
        返回适合调试和日志输出的字符串表示。
        """
        return f"Proxyserver({len(self.connections)} active conns)"

    @command.command("proxyserver.active_connections")
    def active_connections(self) -> int:
        """
        `proxyserver.active_connections` 命令：返回当前 live connection handler 数。
        """
        return len(self.connections)

    @contextmanager
    def register_connection(
        self, connection_id: tuple | str, handler: ProxyConnectionHandler
    ):
        """
        连接处理器注册上下文。

        代理核心在连接开始时登记 handler，连接结束时自动移除，供注入命令查找
        live 连接。
        """
        self.connections[connection_id] = handler
        try:
            # 使用生成器，这里外面 next 拿到的就是注册完成的 connection，直到持有者执行 next/（另一个好像是 send） 才会进入后面的 finally
            yield
        finally:
            del self.connections[connection_id]

    def load(self, loader):
        """
        addon 加载事件：注册代理服务器和 HTTP 传输相关选项。
        """
        loader.add_option(
            "store_streamed_bodies",
            bool,
            False,
            "Store HTTP request and response bodies when streamed (see `stream_large_bodies`). "
            "This increases memory consumption, but makes it possible to inspect streamed bodies.",
        )
        loader.add_option(
            "connection_strategy",
            str,
            "eager",
            "Determine when server connections should be established. When set to lazy, mitmproxy "
            "tries to defer establishing an upstream connection as long as possible. This makes it possible to "
            "use server replay while being offline. When set to eager, mitmproxy can detect protocols with "
            "server-side greetings, as well as accurately mirror TLS ALPN negotiation.",
            choices=("eager", "lazy"),
        )
        loader.add_option(
            "stream_large_bodies",
            Optional[str],
            None,
            """
            Stream data to the client if request or response body exceeds the given
            threshold. If streamed, the body will not be stored in any way,
            and such responses cannot be modified. Understands k/m/g
            suffixes, i.e. 3m for 3 megabytes. To store streamed bodies, see `store_streamed_bodies`.
            """,
        )
        loader.add_option(
            "body_size_limit",
            Optional[str],
            None,
            """
            Byte size limit of HTTP request and response bodies. Understands
            k/m/g suffixes, i.e. 3m for 3 megabytes.
            """,
        )
        loader.add_option(
            "keep_host_header",
            bool,
            False,
            """
            Reverse Proxy: Keep the original host header instead of rewriting it
            to the reverse proxy target.
            """,
        )
        loader.add_option(
            "proxy_debug",
            bool,
            False,
            "Enable debug logs in the proxy core.",
        )
        loader.add_option(
            "normalize_outbound_headers",
            bool,
            True,
            """
            Normalize outgoing HTTP/2 header names, but emit a warning when doing so.
            HTTP/2 does not allow uppercase header names. This option makes sure that HTTP/2 headers set
            in custom scripts are lowercased before they are sent.
            """,
        )
        loader.add_option(
            "validate_inbound_headers",
            bool,
            True,
            """
            Make sure that incoming HTTP requests are not malformed.
            Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.
            """,
        )
        loader.add_option(
            "connect_addr",
            Optional[str],
            None,
            """Set the local IP address that mitmproxy should use when connecting to upstream servers.""",
        )

    def running(self):
        """
        `running` 事件：mitmproxy 启动完成后触发，允许后续 configure 动态更新监听实例。
        """
        self.is_running = True

    def configure(self, updated) -> None:
        """
        `configure` 事件：选项变化后触发。

        校验 body 大小配置、出站本地地址、代理 mode 语法和监听地址冲突；运行态
        下 mode/server 改变会异步更新实际监听服务器。
        """
        if "stream_large_bodies" in updated:
            try:
                human.parse_size(ctx.options.stream_large_bodies)
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid stream_large_bodies specification: "
                    f"{ctx.options.stream_large_bodies}"
                )
        if "body_size_limit" in updated:
            try:
                human.parse_size(ctx.options.body_size_limit)
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid body_size_limit specification: "
                    f"{ctx.options.body_size_limit}"
                )
        if "connect_addr" in updated:
            try:
                if ctx.options.connect_addr:
                    self._connect_addr = (
                        str(ipaddress.ip_address(ctx.options.connect_addr)),
                        0,
                    )
                else:
                    self._connect_addr = None
            except ValueError:
                raise exceptions.OptionsError(
                    f"Invalid value for connect_addr: {ctx.options.connect_addr!r}. Specify a valid IP address."
                )
        if "mode" in updated or "server" in updated:
            # Make sure that all modes are syntactically valid...
            modes: list[mode_specs.ProxyMode] = []
            for mode in ctx.options.mode:
                try:
                    modes.append(mode_specs.ProxyMode.parse(mode))
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Invalid proxy mode specification: {mode} ({e})"
                    )

            # ...and don't listen on the same address.
            listen_addrs = []
            for m in modes:
                if m.transport_protocol == "both":
                    protocols = ["tcp", "udp"]
                else:
                    protocols = [m.transport_protocol]
                host = m.listen_host(ctx.options.listen_host)
                port = m.listen_port(ctx.options.listen_port)
                if port is None:
                    continue
                for proto in protocols:
                    listen_addrs.append((host, port, proto))
            if len(set(listen_addrs)) != len(listen_addrs):
                (host, port, _) = collections.Counter(listen_addrs).most_common(1)[0][0]
                dup_addr = human.format_address((host or "0.0.0.0", port))
                raise exceptions.OptionsError(
                    f"Cannot spawn multiple servers on the same address: {dup_addr}"
                )

            if ctx.options.mode and not ctx.master.addons.get("nextlayer"):
                logger.warning("Warning: Running proxyserver without nextlayer addon!")
            if any(isinstance(m, mode_specs.TransparentMode) for m in modes):
                if platform.original_addr:
                    platform.init_transparent_mode()
                else:
                    raise exceptions.OptionsError(
                        "Transparent mode not supported on this platform."
                    )

            if self.is_running:
                asyncio_utils.create_task(
                    self.servers.update(modes),
                    name="update servers",
                    keep_ref=True,
                )

    async def setup_servers(self) -> bool:
        """
        Setup proxy servers. This may take an indefinite amount of time to complete (e.g. on permission prompts).
        
        中文说明：master 启动代理时调用。某些平台可能需要权限提示，因此这是
        async 方法并可能等待较久。
        """
        return await self.servers.update(
            [mode_specs.ProxyMode.parse(m) for m in ctx.options.mode]
        )

    def listen_addrs(self) -> list[Address]:
        """
        返回当前所有监听实例的地址列表。
        """
        return [addr for server in self.servers for addr in server.listen_addrs]

    def inject_event(self, event: events.MessageInjected):
        """
        向已有连接或 flow 注入用户构造的协议事件。
        """
        connection_id: str | tuple
        if event.flow.client_conn.transport_protocol != "udp":
            connection_id = event.flow.client_conn.id
        else:  # pragma: no cover
            # temporary workaround: for UDP we don't have persistent client IDs yet.
            connection_id = (
                event.flow.client_conn.peername,
                event.flow.client_conn.sockname,
            )
        if connection_id not in self.connections:
            raise ValueError("Flow is not from a live connection.")

        asyncio_utils.create_task(
            self.connections[connection_id].server_event(event),
            name=f"inject_event",
            keep_ref=True,
            client=event.flow.client_conn.peername,
        )

    @command.command("inject.websocket")
    def inject_websocket(
        self, flow: Flow, to_client: bool, message: bytes, is_text: bool = True
    ):
        """
        `inject.websocket` 命令：向 live WebSocket flow 注入一条消息。
        """
        if not isinstance(flow, http.HTTPFlow) or not flow.websocket:
            logger.warning("Cannot inject WebSocket messages into non-WebSocket flows.")
            return

        msg = websocket.WebSocketMessage(
            Opcode.TEXT if is_text else Opcode.BINARY, not to_client, message
        )
        event = WebSocketMessageInjected(flow, msg)
        try:
            self.inject_event(event)
        except ValueError as e:
            logger.warning(str(e))

    @command.command("inject.tcp")
    def inject_tcp(self, flow: Flow, to_client: bool, message: bytes):
        """
        `inject.tcp` 命令：向 live TCP flow 注入一段字节。
        """
        if not isinstance(flow, tcp.TCPFlow):
            logger.warning("Cannot inject TCP messages into non-TCP flows.")
            return

        event = TcpMessageInjected(flow, tcp.TCPMessage(not to_client, message))
        try:
            self.inject_event(event)
        except ValueError as e:
            logger.warning(str(e))

    @command.command("inject.udp")
    def inject_udp(self, flow: Flow, to_client: bool, message: bytes):
        """
        `inject.udp` 命令：向 live UDP flow 注入一个数据报。
        """
        if not isinstance(flow, udp.UDPFlow):
            logger.warning("Cannot inject UDP messages into non-UDP flows.")
            return

        event = UdpMessageInjected(flow, udp.UDPMessage(not to_client, message))
        try:
            self.inject_event(event)
        except ValueError as e:
            logger.warning(str(e))

    def server_connect(self, data: server_hooks.ServerConnectionHookData):
        """
        `server_connect` 事件：代理即将建立上游连接时触发。

        这里设置可选的本地出站地址，并阻止 mitmproxy 递归连接到自身监听端口。
        """
        if data.server.sockname is None:
            data.server.sockname = self._connect_addr

        # Prevent mitmproxy from recursively connecting to itself.
        assert data.server.address
        connect_host, connect_port, *_ = data.server.address

        for server in self.servers:
            for listen_host, listen_port, *_ in server.listen_addrs:
                self_connect = (
                    connect_port == listen_port
                    and connect_host in ("localhost", "127.0.0.1", "::1", listen_host)
                    and server.mode.transport_protocol == data.server.transport_protocol
                )
                if self_connect:
                    data.server.error = (
                        "Request destination unknown. "
                        "Unable to figure out where this request should be forwarded to."
                    )
                    return
