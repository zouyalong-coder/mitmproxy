"""
hyper-h2 适配工具。

本模块为 mitmproxy 的 HTTP/2 layer 提供两类辅助：
- `H2ConnectionLogger` 把 hyper-h2 的调试日志接入 mitmproxy 日志体系。
- `BufferedH2Connection` 在 hyper-h2 基础上增加发送缓冲，避免流控窗口不足时
  直接抛错，并保证 DATA 与 trailers 的发送顺序。
"""

import collections
import logging
from typing import NamedTuple

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings
import h2.stream

logger = logging.getLogger(__name__)


class H2ConnectionLogger(h2.config.DummyLogger):
    """
    hyper-h2 日志适配器。

    调试开启时，HTTP/2 帧/状态变化会通过它带上连接 peername 输出。
    """

    def __init__(self, peername: tuple, conn_type: str):
        """记录对端地址和连接类型，用于日志前缀。"""
        super().__init__()
        self.peername = peername
        self.conn_type = conn_type

    def debug(self, fmtstr, *args):
        """转发 hyper-h2 debug 日志。"""
        logger.debug(
            f"{self.conn_type} {fmtstr}", *args, extra={"client": self.peername}
        )

    def trace(self, fmtstr, *args):
        """转发 hyper-h2 trace 日志到更低一级 DEBUG。"""
        logger.log(
            logging.DEBUG - 1,
            f"{self.conn_type} {fmtstr}",
            *args,
            extra={"client": self.peername},
        )


class SendH2Data(NamedTuple):
    """
    被流控阻塞时暂存的一段 HTTP/2 DATA。
    """

    data: bytes
    end_stream: bool


class BufferedH2Connection(h2.connection.H2Connection):
    """
    This class wrap's hyper-h2's H2Connection and adds internal send buffers.

    To simplify implementation, padding is unsupported.

    中文说明：当单个 stream 或整条连接的流控窗口不足时，`send_data()` 不会
    失败，而是把剩余 DATA 暂存，等待 WINDOW_UPDATE 后继续发送。
    """

    stream_buffers: collections.defaultdict[int, collections.deque[SendH2Data]]
    stream_trailers: dict[int, list[tuple[bytes, bytes]]]

    def __init__(self, config: h2.config.H2Configuration):
        """初始化大窗口设置、发送缓冲区和 trailers 暂存区。"""
        super().__init__(config)
        self.local_settings.initial_window_size = 2**31 - 1
        self.local_settings.max_frame_size = 2**17
        self.max_inbound_frame_size = 2**17
        # hyper-h2 pitfall: we need to acknowledge here, otherwise its sends out the old settings.
        self.local_settings.acknowledge()
        self.stream_buffers = collections.defaultdict(collections.deque)
        self.stream_trailers = {}

    def initiate_connection(self):
        """
        启动 HTTP/2 连接，并把连接级流控窗口扩到最大。
        """
        super().initiate_connection()
        # We increase the flow-control window for new streams with a setting,
        # but we need to increase the overall connection flow-control window as well.
        self.increment_flow_control_window(
            2**31 - 1 - self.inbound_flow_control_window
        )  # maximum - default

    def send_data(
        self,
        stream_id: int,
        data: bytes,
        end_stream: bool = False,
        pad_length: None = None,
    ) -> None:
        """
        Send data on a given stream.

        In contrast to plain hyper-h2, this method will not raise if the data cannot be sent immediately.
        Data is split up and buffered internally.
        """
        frame_size = len(data)
        assert pad_length is None

        if frame_size > self.max_outbound_frame_size:
            for start in range(0, frame_size, self.max_outbound_frame_size):
                chunk = data[start : start + self.max_outbound_frame_size]
                self.send_data(stream_id, chunk, end_stream=False)

            return

        if self.stream_buffers.get(stream_id, None):
            # We already have some data buffered, let's append.
            self.stream_buffers[stream_id].append(SendH2Data(data, end_stream))
        else:
            available_window = self.local_flow_control_window(stream_id)
            if frame_size <= available_window:
                super().send_data(stream_id, data, end_stream)
            else:
                if available_window:
                    can_send_now = data[:available_window]
                    super().send_data(stream_id, can_send_now, end_stream=False)
                    data = data[available_window:]
                # We can't send right now, so we buffer.
                self.stream_buffers[stream_id].append(SendH2Data(data, end_stream))

    def send_trailers(self, stream_id: int, trailers: list[tuple[bytes, bytes]]):
        """
        发送 trailers；如果前面还有 DATA 被缓冲，则 trailers 必须排在 DATA 后。
        """
        if self.stream_buffers.get(stream_id, None):
            # Though trailers are not subject to flow control, we need to queue them and send strictly after data frames
            self.stream_trailers[stream_id] = trailers
        else:
            self.send_headers(stream_id, trailers, end_stream=True)

    def end_stream(self, stream_id: int) -> None:
        """
        结束 stream；若 trailers 已排队，则由 trailers 的 HEADERS 帧负责结束。
        """
        if stream_id in self.stream_trailers:
            return  # we already have trailers queued up that will end the stream.
        self.send_data(stream_id, b"", end_stream=True)

    def reset_stream(self, stream_id: int, error_code: int = 0) -> None:
        """重置 stream 前先清理对应发送缓冲。"""
        self.stream_buffers.pop(stream_id, None)
        super().reset_stream(stream_id, error_code)

    def receive_data(self, data: bytes):
        """
        接收 HTTP/2 帧并响应流控相关事件。

        WINDOW_UPDATE 或 initial window size 变化会触发缓冲数据继续发送。
        """
        events = super().receive_data(data)
        ret = []
        for event in events:
            if isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    self.connection_window_updated()
                else:
                    self.stream_window_updated(event.stream_id)
                continue
            elif isinstance(event, h2.events.RemoteSettingsChanged):
                if (
                    h2.settings.SettingCodes.INITIAL_WINDOW_SIZE
                    in event.changed_settings
                ):
                    self.connection_window_updated()
            elif isinstance(event, h2.events.StreamReset):
                self.stream_buffers.pop(event.stream_id, None)
            elif isinstance(event, h2.events.ConnectionTerminated):
                self.stream_buffers.clear()
            ret.append(event)
        return ret

    def stream_window_updated(self, stream_id: int) -> bool:
        """
        The window for a specific stream has updated. Send as much buffered data as possible.

        中文说明：单个 stream 的窗口更新后，从该 stream 的缓冲队列里尽量发送。
        """
        # If the stream has been reset in the meantime, we just clear the buffer.
        try:
            stream: h2.stream.H2Stream = self.streams[stream_id]
        except KeyError:
            stream_was_reset = True
        else:
            stream_was_reset = stream.state_machine.state not in (
                h2.stream.StreamState.OPEN,
                h2.stream.StreamState.HALF_CLOSED_REMOTE,
            )
        if stream_was_reset:
            self.stream_buffers.pop(stream_id, None)
            return False

        available_window = self.local_flow_control_window(stream_id)
        sent_any_data = False
        while available_window > 0 and stream_id in self.stream_buffers:
            chunk: SendH2Data = self.stream_buffers[stream_id].popleft()
            if len(chunk.data) > available_window:
                # We can't send the entire chunk, so we have to put some bytes back into the buffer.
                self.stream_buffers[stream_id].appendleft(
                    SendH2Data(
                        data=chunk.data[available_window:],
                        end_stream=chunk.end_stream,
                    )
                )
                chunk = SendH2Data(
                    data=chunk.data[:available_window],
                    end_stream=False,
                )

            super().send_data(stream_id, data=chunk.data, end_stream=chunk.end_stream)

            available_window -= len(chunk.data)
            if not self.stream_buffers[stream_id]:
                del self.stream_buffers[stream_id]
                if stream_id in self.stream_trailers:
                    self.send_headers(
                        stream_id, self.stream_trailers.pop(stream_id), end_stream=True
                    )
            sent_any_data = True

        return sent_any_data

    def connection_window_updated(self) -> None:
        """
        The connection window has updated. Send data from buffers in a round-robin fashion.

        中文说明：连接级窗口更新后，在多个 stream 的缓冲队列间轮询发送，避免某个
        stream 长时间独占窗口。
        """
        sent_any_data = True
        while sent_any_data:
            sent_any_data = False
            for stream_id in list(self.stream_buffers):
                self.stream_buffers[stream_id] = self.stream_buffers.pop(
                    stream_id
                )  # move to end of dict
                if self.stream_window_updated(stream_id):
                    sent_any_data = True
                    if self.outbound_flow_control_window == 0:
                        return
