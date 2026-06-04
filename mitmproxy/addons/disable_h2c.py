"""
禁用明文 HTTP/2 h2c 升级的内置 addon。

触发点：
- `request`：HTTP 请求发往上游前触发，删除 h2c Upgrade 头或 kill prior knowledge 请求。
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
    
    中文说明：mitmproxy 当前只支持 TLS 上的 HTTP/2。这个 addon 在请求阶段阻止
    客户端把明文 HTTP/1.1 连接升级成 h2c，避免后续协议层收到无法处理的帧。
    """

    def process_flow(self, f):
        """
        检查并处理 h2c Upgrade 或 HTTP/2 prior knowledge 请求。
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
        HTTP `request` 事件：请求发往上游前触发。
        """
        self.process_flow(f)
