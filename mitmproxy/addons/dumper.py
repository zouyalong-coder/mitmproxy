"""
`mitmproxy.addons.dumper` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from __future__ import annotations

import shutil
import sys
from typing import IO
from typing import Optional

from wsproto.frame_protocol import CloseReason

import mitmproxy_rs
from mitmproxy import contentviews
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.contrib import click as miniclick
from mitmproxy.net.dns import response_codes
from mitmproxy.options import CONTENT_VIEW_LINES_CUTOFF
from mitmproxy.tcp import TCPFlow
from mitmproxy.tcp import TCPMessage
from mitmproxy.udp import UDPFlow
from mitmproxy.udp import UDPMessage
from mitmproxy.utils import human
from mitmproxy.utils import strutils
from mitmproxy.utils import vt_codes
from mitmproxy.websocket import WebSocketData
from mitmproxy.websocket import WebSocketMessage


def indent(n: int, text: str) -> str:
    """
    给多行文本增加缩进，用于命令行输出排版。
    """
    lines = str(text).strip().splitlines()
    pad = " " * n
    return "\n".join(pad + i for i in lines)


CONTENTVIEW_STYLES: dict[str, dict[str, str | bool]] = {
    "name": dict(fg="yellow"),
    "string": dict(fg="green"),
    "number": dict(fg="blue"),
    "boolean": dict(fg="magenta"),
    "comment": dict(dim=True),
    "error": dict(fg="red"),
}


class Dumper:
    """
    `dumper` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def __init__(self, outfile: IO[str] | None = None):
        """
        初始化对象状态。
        """
        self.filter: flowfilter.TFilter | None = None
        self.outfp: IO[str] = outfile or sys.stdout
        self.out_has_vt_codes = vt_codes.ensure_supported(self.outfp)

    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "flow_detail",
            int,
            1,
            f"""
            The display detail level for flows in mitmdump: 0 (quiet) to 4 (very verbose).
              0: no output
              1: shortened request URL with response status code
              2: full request URL with response status code and HTTP headers
              3: 2 + truncated response content, content of WebSocket and TCP messages (content_view_lines_cutoff: {CONTENT_VIEW_LINES_CUTOFF})
              4: 3 + nothing is truncated
            """,
        )
        loader.add_option(
            "dumper_default_contentview",
            str,
            "auto",
            "The default content view mode.",
            choices=contentviews.registry.available_views(),
        )
        loader.add_option(
            "dumper_filter", Optional[str], None, "Limit which flows are dumped."
        )

    def configure(self, updated):
        """
        在相关配置项变化时重新读取、校验并缓存运行参数。
        """
        if "dumper_filter" in updated:
            if ctx.options.dumper_filter:
                try:
                    self.filter = flowfilter.parse(ctx.options.dumper_filter)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            else:
                self.filter = None

    def style(self, text: str, **style) -> str:
        """
        `dumper` addon 中的方法，用于处理 `style` 相关逻辑。
        """
        if style and self.out_has_vt_codes:
            text = miniclick.style(text, **style)
        return text

    def echo(self, text: str, ident=None, **style):
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        if ident:
            text = indent(ident, text)
        text = self.style(text, **style)
        print(text, file=self.outfp)

    def _echo_headers(self, headers: http.Headers):
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        for k, v in headers.fields:
            ks = strutils.bytes_to_escaped_str(k)
            ks = self.style(ks, fg="blue")
            vs = strutils.bytes_to_escaped_str(v)
            self.echo(f"{ks}: {vs}", ident=4)

    def _echo_trailers(self, trailers: http.Headers | None):
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        if not trailers:
            return
        self.echo("--- HTTP Trailers", fg="magenta", ident=4)
        self._echo_headers(trailers)

    def _echo_message(
        self,
        message: http.Message | TCPMessage | UDPMessage | WebSocketMessage,
        flow: http.HTTPFlow | TCPFlow | UDPFlow,
    ):
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        pretty = contentviews.prettify_message(
            message,
            flow,
            ctx.options.dumper_default_contentview,
        )

        if ctx.options.flow_detail == 3:
            content_to_echo = strutils.cut_after_n_lines(
                pretty.text, ctx.options.content_view_lines_cutoff
            )
        else:
            content_to_echo = pretty.text

        if content_to_echo:
            highlighted = mitmproxy_rs.syntax_highlight.highlight(
                pretty.text, pretty.syntax_highlight
            )
            self.echo("")
            self.echo(
                "".join(
                    self.style(chunk, **CONTENTVIEW_STYLES.get(tag, {}))
                    for tag, chunk in highlighted
                ),
                ident=4,
            )

        if len(content_to_echo) < len(pretty.text):
            self.echo("(cut off)", ident=4, dim=True)

        if ctx.options.flow_detail >= 2:
            self.echo("")

    def _fmt_client(self, flow: flow.Flow) -> str:
        """
        格式化数据以便展示、保存或导出。
        """
        if flow.is_replay == "request":
            return self.style("[replay]", fg="yellow", bold=True)
        elif flow.client_conn.peername:
            return self.style(
                strutils.escape_control_characters(
                    human.format_address(flow.client_conn.peername)
                )
            )
        else:  # pragma: no cover
            # this should not happen, but we're defensive here.
            return ""

    def _echo_request_line(self, flow: http.HTTPFlow) -> None:
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        client = self._fmt_client(flow)

        pushed = " PUSH_PROMISE" if "h2-pushed-stream" in flow.metadata else ""
        method = flow.request.method + pushed
        method_color = dict(GET="green", DELETE="red").get(method.upper(), "magenta")
        method = self.style(
            strutils.escape_control_characters(method), fg=method_color, bold=True
        )
        if ctx.options.showhost:
            url = flow.request.pretty_url
        else:
            url = flow.request.url

        if ctx.options.flow_detail == 1:
            # We need to truncate before applying styles, so we just focus on the URL.
            terminal_width_limit = max(shutil.get_terminal_size()[0] - 25, 50)
            if len(url) > terminal_width_limit:
                url = url[:terminal_width_limit] + "…"
        url = self.style(strutils.escape_control_characters(url), bold=True)

        http_version = ""
        if not (
            flow.request.is_http10 or flow.request.is_http11
        ) or flow.request.http_version != getattr(
            flow.response, "http_version", "HTTP/1.1"
        ):
            # Hide version for h1 <-> h1 connections.
            http_version = " " + flow.request.http_version

        self.echo(f"{client}: {method} {url}{http_version}")

    def _echo_response_line(self, flow: http.HTTPFlow) -> None:
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        if flow.is_replay == "response":
            replay_str = "[replay]"
            replay = self.style(replay_str, fg="yellow", bold=True)
        else:
            replay_str = ""
            replay = ""

        assert flow.response
        code_int = flow.response.status_code
        code_color = None
        if 200 <= code_int < 300:
            code_color = "green"
        elif 300 <= code_int < 400:
            code_color = "magenta"
        elif 400 <= code_int < 600:
            code_color = "red"
        code = self.style(
            str(code_int),
            fg=code_color,
            bold=True,
            blink=(code_int == 418),
        )

        if not (flow.response.is_http2 or flow.response.is_http3):
            reason = flow.response.reason
        else:
            reason = http.status_codes.RESPONSES.get(flow.response.status_code, "")
        reason = self.style(
            strutils.escape_control_characters(reason), fg=code_color, bold=True
        )

        if flow.response.raw_content is None:
            size = "(content missing)"
        else:
            size = human.pretty_size(len(flow.response.raw_content))
        size = self.style(size, bold=True)

        http_version = ""
        if (
            not (flow.response.is_http10 or flow.response.is_http11)
            or flow.request.http_version != flow.response.http_version
        ):
            # Hide version for h1 <-> h1 connections.
            http_version = f"{flow.response.http_version} "

        arrows = self.style(" <<", bold=True)
        if ctx.options.flow_detail == 1:
            # This aligns the HTTP response code with the HTTP request method:
            # 127.0.0.1:59519: GET http://example.com/
            #               << 304 Not Modified 0b
            pad = max(
                0,
                len(human.format_address(flow.client_conn.peername))
                - (2 + len(http_version) + len(replay_str)),
            )
            arrows = " " * pad + arrows

        self.echo(f"{replay}{arrows} {http_version}{code} {reason} {size}")

    def echo_flow(self, f: http.HTTPFlow) -> None:
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        if f.request:
            self._echo_request_line(f)
            if ctx.options.flow_detail >= 2:
                self._echo_headers(f.request.headers)
            if ctx.options.flow_detail >= 3:
                self._echo_message(f.request, f)
            if ctx.options.flow_detail >= 2:
                self._echo_trailers(f.request.trailers)

        if f.response:
            self._echo_response_line(f)
            if ctx.options.flow_detail >= 2:
                self._echo_headers(f.response.headers)
            if ctx.options.flow_detail >= 3:
                self._echo_message(f.response, f)
            if ctx.options.flow_detail >= 2:
                self._echo_trailers(f.response.trailers)

        if f.error:
            msg = strutils.escape_control_characters(f.error.msg)
            self.echo(f" << {msg}", bold=True, fg="red")

        self.outfp.flush()

    def match(self, f):
        """
        根据过滤器或当前配置判断 flow 是否匹配。
        """
        if ctx.options.flow_detail == 0:
            return False
        if not self.filter:
            return True
        elif flowfilter.match(self.filter, f):
            return True
        return False

    def response(self, f):
        """
        处理 HTTP 响应生命周期事件，可读取或修改 response flow。
        """
        if self.match(f):
            self.echo_flow(f)

    def error(self, f):
        """
        处理 HTTP flow 的协议或连接错误事件。
        """
        if self.match(f):
            self.echo_flow(f)

    def http_connect_error(self, f):
        """
        处理 HTTP CONNECT 建隧道失败事件。
        """
        if self.match(f):
            self.echo_flow(f)

    def websocket_message(self, f: http.HTTPFlow):
        """
        处理 WebSocket 消息事件。
        """
        assert f.websocket is not None  # satisfy type checker
        if self.match(f):
            message = f.websocket.messages[-1]

            direction = "->" if message.from_client else "<-"
            self.echo(
                f"{human.format_address(f.client_conn.peername)} "
                f"{direction} WebSocket {message.type.name.lower()} message "
                f"{direction} {human.format_address(f.server_conn.address)}{f.request.path}"
            )
            if ctx.options.flow_detail >= 3:
                self._echo_message(message, f)

    def websocket_end(self, f: http.HTTPFlow):
        """
        处理 WebSocket 连接结束事件。
        """
        assert f.websocket is not None  # satisfy type checker
        if self.match(f):
            if f.websocket.close_code in {1000, 1001, 1005}:
                c = "client" if f.websocket.closed_by_client else "server"
                self.echo(
                    f"WebSocket connection closed by {c}: {f.websocket.close_code} {f.websocket.close_reason}"
                )
            else:
                error = flow.Error(
                    f"WebSocket Error: {self.format_websocket_error(f.websocket)}"
                )
                self.echo(
                    f"Error in WebSocket connection to {human.format_address(f.server_conn.address)}: {error}",
                    fg="red",
                )

    def format_websocket_error(self, websocket: WebSocketData) -> str:
        """
        格式化数据以便展示、保存或导出。
        """
        try:
            ret = CloseReason(websocket.close_code).name  # type: ignore
        except ValueError:
            ret = f"UNKNOWN_ERROR={websocket.close_code}"
        if websocket.close_reason:
            ret += f" (reason: {websocket.close_reason})"
        return ret

    def _proto_error(self, f):
        """
        `dumper` addon 的内部辅助方法。
        """
        if self.match(f):
            self.echo(
                f"Error in {f.type.upper()} connection to {human.format_address(f.server_conn.address)}: {f.error}",
                fg="red",
            )

    def tcp_error(self, f):
        """
        处理 TCP flow 错误事件。
        """
        self._proto_error(f)

    def udp_error(self, f):
        """
        处理 UDP flow 错误事件。
        """
        self._proto_error(f)

    def _proto_message(self, f: TCPFlow | UDPFlow) -> None:
        """
        `dumper` addon 的内部辅助方法。
        """
        if self.match(f):
            message = f.messages[-1]
            direction = "->" if message.from_client else "<-"
            if f.client_conn.tls_version == "QUICv1":
                if f.type == "tcp":
                    quic_type = "stream"
                else:
                    quic_type = "dgrams"
                # TODO: This should not be metadata, this should be typed attributes.
                flow_type = (
                    f"quic {quic_type} {f.metadata.get('quic_stream_id_client', '')} "
                    f"{direction} mitmproxy {direction} "
                    f"quic {quic_type} {f.metadata.get('quic_stream_id_server', '')}"
                )
            else:
                flow_type = f.type
            self.echo(
                "{client} {direction} {type} {direction} {server}".format(
                    client=human.format_address(f.client_conn.peername),
                    server=human.format_address(f.server_conn.address),
                    direction=direction,
                    type=flow_type,
                )
            )
            if ctx.options.flow_detail >= 3:
                self._echo_message(message, f)

    def tcp_message(self, f):
        """
        处理 TCP 消息事件。
        """
        self._proto_message(f)

    def udp_message(self, f):
        """
        处理 UDP 消息事件。
        """
        self._proto_message(f)

    def _echo_dns_query(self, f: dns.DNSFlow) -> None:
        """
        把 flow 或协议消息格式化并输出到命令行。
        """
        client = self._fmt_client(f)
        opcode = dns.op_codes.to_str(f.request.op_code)
        type = dns.types.to_str(f.request.questions[0].type)

        desc = f"DNS {opcode} ({type})"
        desc_color = {
            "A": "green",
            "AAAA": "magenta",
        }.get(type, "red")
        desc = self.style(desc, fg=desc_color)

        name = self.style(f.request.questions[0].name, bold=True)
        self.echo(f"{client}: {desc} {name}")

    def dns_response(self, f: dns.DNSFlow):
        """
        处理 DNS 响应事件。
        """
        assert f.response
        if self.match(f):
            self._echo_dns_query(f)

            arrows = self.style(" <<", bold=True)
            if f.response.answers:
                answers = ", ".join(
                    self.style(str(x), fg="bright_blue") for x in f.response.answers
                )
            else:
                answers = self.style(
                    response_codes.to_str(
                        f.response.response_code,
                    ),
                    fg="red",
                )
            self.echo(f"{arrows} {answers}")

    def dns_error(self, f: dns.DNSFlow):
        """
        处理 DNS flow 错误事件。
        """
        assert f.error
        if self.match(f):
            self._echo_dns_query(f)
            msg = strutils.escape_control_characters(f.error.msg)
            self.echo(f" << {msg}", bold=True, fg="red")
