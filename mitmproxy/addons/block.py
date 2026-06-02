"""
`mitmproxy.addons.block` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import ipaddress
import logging

from mitmproxy import ctx
from mitmproxy.proxy import mode_specs


class Block:
    """
    `block` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
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
        处理客户端连接建立事件。
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
