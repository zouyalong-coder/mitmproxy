"""
This module contains a very terrible QUIC client hello parser.

Nothing is more permanent than a temporary solution!

中文说明：mitmproxy 需要在真正建立 aioquic 服务器连接前获知客户端 QUIC
ClientHello 中的 SNI/ALPN。这里通过临时接管 aioquic TLS 处理函数，在解析到
ClientHello 时用异常把原始 TLS ClientHello 抛出来，再复用 mitmproxy 的
`ClientHello` 解析器。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from aioquic.buffer import Buffer as QuicBuffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.connection import QuicConnectionError
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import PACKET_TYPE_INITIAL
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import HandshakeType

from mitmproxy.tls import ClientHello


@dataclass
class QuicClientHello(Exception):
    """
    Helper error only used in `quic_parse_client_hello_from_datagrams`.

    中文说明：用异常短路 aioquic 的握手流程，把 ClientHello 原始字节带出来。
    """

    data: bytes


def quic_parse_client_hello_from_datagrams(
    datagrams: list[bytes],
) -> Optional[ClientHello]:
    """
    Check if the supplied bytes contain a full ClientHello message,
    and if so, parse it.

    Args:
        - msgs: list of ClientHello fragments received from client

    Returns:
        - A ClientHello object on success
        - None, if the QUIC record is incomplete

    Raises:
        - A ValueError, if the passed ClientHello is invalid

    中文说明：触发点是客户端 QUIC Initial datagram 到达。QUIC ClientHello 可能
    跨多个 datagram 分片，因此输入是 datagram 列表；如果还不完整则返回 None。
    """

    # ensure the first packet is indeed the initial one
    buffer = QuicBuffer(data=datagrams[0])
    header = pull_quic_header(buffer, 8)
    if header.packet_type != PACKET_TYPE_INITIAL:
        raise ValueError("Packet is not initial one.")

    # patch aioquic to intercept the client hello
    quic = QuicConnection(
        configuration=QuicConfiguration(
            is_client=False,
            certificate="",
            private_key="",
            quic_logger=QuicLogger(),
        ),
        original_destination_connection_id=header.destination_cid,
    )
    _initialize = quic._initialize

    def server_handle_hello_replacement(
        input_buf: QuicBuffer,
        initial_buf: QuicBuffer,
        handshake_buf: QuicBuffer,
        onertt_buf: QuicBuffer,
    ) -> None:
        """
        替换 aioquic 的 server hello 处理函数，截获 TLS ClientHello。
        """
        assert input_buf.pull_uint8() == HandshakeType.CLIENT_HELLO
        length = 0
        for b in input_buf.pull_bytes(3):
            length = (length << 8) | b
        offset = input_buf.tell()
        raise QuicClientHello(input_buf.data_slice(offset, offset + length))

    def initialize_replacement(peer_cid: bytes) -> None:
        """
        在 aioquic 初始化完成后替换 TLS ClientHello handler。
        """
        try:
            return _initialize(peer_cid)
        finally:
            quic.tls._server_handle_hello = server_handle_hello_replacement  # type: ignore

    quic._initialize = initialize_replacement  # type: ignore
    try:
        for dgm in datagrams:
            quic.receive_datagram(dgm, ("0.0.0.0", 0), now=time.time())
    except QuicClientHello as hello:
        try:
            return ClientHello(hello.data)
        except EOFError as e:
            raise ValueError("Invalid ClientHello data.") from e
    except QuicConnectionError as e:
        raise ValueError(e.reason_phrase) from e

    quic_logger = quic._configuration.quic_logger
    assert isinstance(quic_logger, QuicLogger)
    traces = quic_logger.to_dict().get("traces")
    assert isinstance(traces, list)
    for trace in traces:
        quic_events = trace.get("events")
        for event in quic_events:
            if event["name"] == "transport:packet_dropped":
                raise ValueError(
                    f"Invalid ClientHello packet: {event['data']['trigger']}"
                )

    return None  # pragma: no cover  # FIXME: this should have test coverage
