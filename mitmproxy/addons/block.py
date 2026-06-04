"""
按客户端 IP 类型拒绝连接的内置 addon。

触发点：
- `load`：addon 加载时注册 `block_global` 和 `block_private`。
- `client_connected`：客户端 TCP 连接刚进入 mitmproxy 时触发，用于在协议解析前拦截来源。
"""

import ipaddress
import logging

from mitmproxy import ctx
from mitmproxy.proxy import mode_specs


class Block:
    """
    根据客户端地址是否为公网/私网地址决定是否立即拒绝连接。
    """

    def load(self, loader):
        """
        addon 加载事件：注册连接来源限制选项。
        """
        loader.add_option(
            "block_global",
            bool,
            True,
            """
            Block connections from public IP addresses.
            """,
        )
        loader.add_option(
            "block_private",
            bool,
            False,
            """
            Block connections from local (private) IP addresses.
            This option does not affect loopback addresses (connections from the local machine),
            which are always permitted.
            """,
        )

    def client_connected(self, client):
        """
        `client_connected` 事件：客户端连接建立后、进入具体协议层前触发。

        这里通过设置 `client.error` 终止连接。回环地址和 LocalMode 始终允许，
        避免阻断本机主动发起的代理流量。
        """
        parts = client.peername[0].rsplit("%", 1)
        address = ipaddress.ip_address(parts[0])
        if isinstance(address, ipaddress.IPv6Address):
            address = address.ipv4_mapped or address

        if address.is_loopback or isinstance(client.proxy_mode, mode_specs.LocalMode):
            return

        if ctx.options.block_private and address.is_private:
            logging.warning(
                f"Client connection from {client.peername[0]} killed by block_private option."
            )
            client.error = "Connection killed by block_private."

        if ctx.options.block_global and address.is_global:
            logging.warning(
                f"Client connection from {client.peername[0]} killed by block_global option."
            )
            client.error = "Connection killed by block_global."
