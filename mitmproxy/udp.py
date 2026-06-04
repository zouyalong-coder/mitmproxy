"""
UDP 流的数据模型。

UDP 是面向数据报的协议，mitmproxy 会把每个数据报保存为一个
`UDPMessage`，并按观察顺序放入 `UDPFlow.messages`。与 TCP 不同，这里的
message 边界就是真实 UDP datagram 边界。
"""

import time

from mitmproxy import connection
from mitmproxy import flow
from mitmproxy.coretypes import serializable


class UDPMessage(serializable.Serializable):
    """
    An individual UDP datagram.

    中文说明：表示单个 UDP 数据报，包含方向、原始内容和接收/创建时间。
    """

    def __init__(self, from_client, content, timestamp=None):
        """
        创建一个 UDP 数据报记录。

        `from_client` 标记数据报方向；`content` 保持原始字节，避免因为编码
        假设导致内容损坏。
        """
        self.from_client = from_client
        self.content = content
        self.timestamp = timestamp or time.time()

    @classmethod
    def from_state(cls, state):
        return cls(*state)

    def get_state(self):
        return self.from_client, self.content, self.timestamp

    def set_state(self, state):
        self.from_client, self.content, self.timestamp = state

    def __repr__(self):
        return "{direction} {content}".format(
            direction="->" if self.from_client else "<-", content=repr(self.content)
        )


class UDPFlow(flow.Flow):
    """
    A UDPFlow is a representation of a UDP session.

    中文说明：UDP 没有连接握手，但 mitmproxy 仍按客户端/服务端地址把一组
    相关数据报组织成一个 Flow，方便统一展示、保存和脚本处理。
    """

    messages: list[UDPMessage]
    """
    The messages transmitted over this connection.

    The latest message can be accessed as `flow.messages[-1]` in event hooks.
    """

    def __init__(
        self,
        client_conn: connection.Client,
        server_conn: connection.Server,
        live: bool = False,
    ):
        super().__init__(client_conn, server_conn, live)
        self.messages = []

    def get_state(self) -> serializable.State:
        return {
            **super().get_state(),
            "messages": [m.get_state() for m in self.messages],
        }

    def set_state(self, state: serializable.State) -> None:
        self.messages = [UDPMessage.from_state(m) for m in state.pop("messages")]
        super().set_state(state)

    def __repr__(self):
        return f"<UDPFlow ({len(self.messages)} messages)>"


__all__ = [
    "UDPFlow",
    "UDPMessage",
]
