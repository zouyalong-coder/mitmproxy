"""
TCP 流的轻量数据模型。

TCP 本质上是字节流，没有应用层“消息”边界。mitmproxy 为了让事件钩子、
UI 和序列化更容易处理，会把传输过程中观察到的字节块包装成 `TCPMessage`，
再挂到 `TCPFlow.messages` 上。
"""

import time

from mitmproxy import connection
from mitmproxy import flow
from mitmproxy.coretypes import serializable


class TCPMessage(serializable.Serializable):
    """
    An individual TCP "message".
    Note that TCP is *stream-based* and not *message-based*.
    For practical purposes the stream is chunked into messages here,
    but you should not rely on message boundaries.

    中文说明：这里的 message 只是 mitmproxy 处理流式数据时切出来的片段，
    不能等同于协议层报文。编写 addon 时应把它视为“这一刻收到/发送的一段
    字节”。
    """

    def __init__(self, from_client, content, timestamp=None):
        """
        创建一个 TCP 字节片段。

        `from_client` 标记方向，`content` 是原始字节，`timestamp` 缺省时使用
        当前时间，方便 UI 和日志按时间展示。
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


class TCPFlow(flow.Flow):
    """
    A TCPFlow is a simplified representation of a TCP session.

    中文说明：TCPFlow 复用 `Flow` 的连接、错误和拦截机制，只额外维护一个
    `messages` 列表，用来按观察顺序保存双向字节片段。
    """

    messages: list[TCPMessage]
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
        self.messages = [TCPMessage.from_state(m) for m in state.pop("messages")]
        super().set_state(state)

    def __repr__(self):
        return f"<TCPFlow ({len(self.messages)} messages)>"


__all__ = [
    "TCPFlow",
    "TCPMessage",
]
