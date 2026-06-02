"""
`mitmproxy.addons.disable_h2c` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

import logging


class DisableH2C:
    """
    We currently only support HTTP/2 over a TLS connection.

    Some clients try to upgrade a connection from HTTP/1.1 to h2c. We need to
    remove those headers to avoid protocol errors if one endpoints suddenly
    starts sending HTTP/2 frames.

    Some clients might use HTTP/2 Prior Knowledge to directly initiate a session
    by sending the connection preface. We just kill those flows.
    
    中文说明：该类封装对应 addon 或辅助对象的状态，并负责上方英文说明所描述的处理流程。
    """

    def process_flow(self, f):
        """
        `disable_h2c` addon 中的方法，用于处理 `process flow` 相关逻辑。
        """
        if f.request.headers.get("upgrade", "") == "h2c":
            logging.warning(
                "HTTP/2 cleartext connections (h2c upgrade requests) are currently not supported."
            )
            del f.request.headers["upgrade"]
            if "connection" in f.request.headers:
                del f.request.headers["connection"]
            if "http2-settings" in f.request.headers:
                del f.request.headers["http2-settings"]

        is_connection_preface = (
            f.request.method == "PRI"
            and f.request.path == "*"
            and f.request.http_version == "HTTP/2.0"
        )
        if is_connection_preface:
            if f.killable:
                f.kill()
            logging.warning(
                "Initiating HTTP/2 connections with prior knowledge are currently not supported."
            )

    # Handlers

    def request(self, f):
        """
        处理 HTTP 请求生命周期事件，可读取或修改 request flow。
        """
        self.process_flow(f)
