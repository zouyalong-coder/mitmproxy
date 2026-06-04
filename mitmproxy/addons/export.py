"""
把单个 flow 导出为 curl、HTTPie 或原始 HTTP 字节的命令型 addon。

触发点：
- `load`：注册导出选项。
- `export.formats`、`export.file`、`export.clip`、`export` 命令：由用户/UI 调用。
- 本 addon 不监听网络生命周期事件，只读取现有 flow 并生成外部表示。
"""

import logging
import shlex
from collections.abc import Callable
from collections.abc import Sequence

import pyperclip

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.net.http.http1 import assemble
from mitmproxy.utils import strutils


def cleanup_request(f: flow.Flow) -> http.Request:
    """
    导出前清理请求对象，去掉或调整不适合重放的字段。
    """
    if not getattr(f, "request", None):
        raise exceptions.CommandError("Can't export flow with no request.")
    assert isinstance(f, http.HTTPFlow)
    request = f.request.copy()
    request.decode(strict=False)
    return request


def pop_headers(request: http.Request) -> None:
    """
    Remove some headers that are redundant for curl/httpie export.
    
    中文说明：删除 curl/httpie 会自动处理或不应重复发送的头，例如
    Content-Length 和可由目标 URL 推导出的 Host。
    """
    request.headers.pop("content-length", None)

    if request.headers.get("host", "") == request.host:
        request.headers.pop("host")
    if request.headers.get(":authority", "") == request.host:
        request.headers.pop(":authority")


def cleanup_response(f: flow.Flow) -> http.Response:
    """
    导出前清理响应对象，去掉或调整不适合重放的字段。
    """
    if not getattr(f, "response", None):
        raise exceptions.CommandError("Can't export flow with no response.")
    assert isinstance(f, http.HTTPFlow)
    response = f.response.copy()  # type: ignore
    response.decode(strict=False)
    return response


def request_content_for_console(request: http.Request) -> str:
    """
    将请求体转换为可安全嵌入 shell 命令的字符串。
    """
    try:
        text = request.get_text(strict=True)
        assert text
    except ValueError:
        # shlex.quote doesn't support a bytes object
        # see https://github.com/python/cpython/pull/10871
        raise exceptions.CommandError("Request content must be valid unicode")
    escape_control_chars = {chr(i): f"\\x{i:02x}" for i in range(32)}
    escaped_text = "".join(escape_control_chars.get(x, x) for x in text)
    if any(char in escape_control_chars for char in text):
        # Escaped chars need to be unescaped by the shell to be properly inperpreted by curl and httpie
        return f'"$(printf {shlex.quote(escaped_text)})"'

    return shlex.quote(escaped_text)


def curl_command(f: flow.Flow) -> str:
    """
    把 HTTPFlow 转换为等价的 curl 命令。
    """
    request = cleanup_request(f)
    pop_headers(request)

    args = ["curl"]

    server_addr = f.server_conn.peername[0] if f.server_conn.peername else None

    if (
        ctx.options.export_preserve_original_ip
        and server_addr
        and request.pretty_host != server_addr
    ):
        resolve = f"{request.pretty_host}:{request.port}:[{server_addr}]"
        args.append("--resolve")
        args.append(resolve)

    for k, v in request.headers.items(multi=True):
        if k.lower() == "accept-encoding":
            args.append("--compressed")
        else:
            args += ["-H", f"{k}: {v}"]

    if request.method != "GET":
        if not request.content:
            # curl will not calculate content-length if there is no content
            # some server/verb combinations require content-length headers
            # (ex. nginx and POST)
            args += ["-H", "content-length: 0"]

        args += ["-X", request.method]

    args.append(request.pretty_url)

    command = " ".join(shlex.quote(arg) for arg in args)
    if request.content:
        command += f" -d {request_content_for_console(request)}"
    return command


def httpie_command(f: flow.Flow) -> str:
    """
    把 HTTPFlow 转换为等价的 HTTPie 命令。
    """
    request = cleanup_request(f)
    pop_headers(request)

    # TODO: Once https://github.com/httpie/httpie/issues/414 is implemented, we
    # should ensure we always connect to the IP address specified in the flow,
    # similar to how it's done in curl_command.
    url = request.pretty_url

    args = ["http", request.method, url]
    for k, v in request.headers.items(multi=True):
        args.append(f"{k}: {v}")
    cmd = " ".join(shlex.quote(arg) for arg in args)
    if request.content:
        cmd += " <<< " + request_content_for_console(request)
    return cmd


def raw_request(f: flow.Flow) -> bytes:
    """
    把 HTTP 请求序列化为原始 HTTP/1 字节。
    """
    request = cleanup_request(f)
    if request.raw_content is None:
        raise exceptions.CommandError("Request content missing.")
    return assemble.assemble_request(request)


def raw_response(f: flow.Flow) -> bytes:
    """
    把 HTTP 响应序列化为原始 HTTP/1 字节。
    """
    response = cleanup_response(f)
    if response.raw_content is None:
        raise exceptions.CommandError("Response content missing.")
    return assemble.assemble_response(response)


def raw(f: flow.Flow, separator=b"\r\n\r\n") -> bytes:
    """
    Return either the request or response if only one exists, otherwise return both
    
    中文说明：如果请求和响应都存在，则用分隔符拼接；WebSocket flow 还会附加
    已格式化的 WebSocket 消息。
    """
    request_present = (
        isinstance(f, http.HTTPFlow) and f.request and f.request.raw_content is not None
    )
    response_present = (
        isinstance(f, http.HTTPFlow)
        and f.response
        and f.response.raw_content is not None
    )

    if request_present and response_present:
        parts = [raw_request(f), raw_response(f)]
        if isinstance(f, http.HTTPFlow) and f.websocket:
            parts.append(f.websocket._get_formatted_messages())
        return separator.join(parts)
    elif request_present:
        return raw_request(f)
    elif response_present:
        return raw_response(f)
    else:
        raise exceptions.CommandError("Can't export flow with no request or response.")


formats: dict[str, Callable[[flow.Flow], str | bytes]] = dict(
    curl=curl_command,
    httpie=httpie_command,
    raw=raw,
    raw_request=raw_request,
    raw_response=raw_response,
)


class Export:
    """
    注册导出命令，并把格式名分派到具体格式化函数。
    """

    def load(self, loader):
        """
        addon 加载事件：注册导出 curl 时是否保留原始 IP 的选项。
        """
        loader.add_option(
            "export_preserve_original_ip",
            bool,
            False,
            """
            When exporting a request as an external command, make an effort to
            connect to the same IP as in the original request. This helps with
            reproducibility in cases where the behaviour depends on the
            particular host we are connecting to. Currently this only affects
            curl exports.
            """,
        )

    @command.command("export.formats")
    def formats(self) -> Sequence[str]:
        """
        Return a list of the supported export formats.
        
        中文说明：命令触发点是 `export.formats`，用于 UI/命令补全展示可用格式。
        """
        return list(sorted(formats.keys()))

    @command.command("export.file")
    def file(self, format: str, flow: flow.Flow, path: mitmproxy.types.Path) -> None:
        """
        Export a flow to path.
        
        中文说明：命令触发点是 `export.file`，把指定格式内容写到文件。
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)
        v = formats[format](flow)
        try:
            with open(path, "wb") as fp:
                if isinstance(v, bytes):
                    fp.write(v)
                else:
                    fp.write(v.encode("utf-8", "surrogateescape"))
        except OSError as e:
            logging.error(str(e))

    @command.command("export.clip")
    def clip(self, format: str, f: flow.Flow) -> None:
        """
        Export a flow to the system clipboard.
        
        中文说明：命令触发点是 `export.clip`，把导出结果写入系统剪贴板。
        """
        content = self.export_str(format, f)
        try:
            pyperclip.copy(content)
        except pyperclip.PyperclipException as e:
            logging.error(str(e))

    @command.command("export")
    def export_str(self, format: str, f: flow.Flow) -> str:
        """
        Export a flow and return the result.
        
        中文说明：命令触发点是 `export`，返回导出结果字符串，供 UI 显示或其他
        命令复用。
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)

        content = formats[format](f)
        # The individual formatters may return surrogate-escaped UTF-8, but that may blow up in later steps.
        # For example, pyperclip on macOS does not like surrogates.
        # To fix this, We first surrogate-encode and then backslash-decode.
        content = strutils.always_bytes(content, "utf8", "surrogateescape")
        content = strutils.always_str(content, "utf8", "backslashreplace")
        return content
