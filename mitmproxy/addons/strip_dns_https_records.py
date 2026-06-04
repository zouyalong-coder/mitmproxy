"""
从 DNS HTTPS/SVCB 记录中移除会影响拦截的参数。

触发点：
- `load`：addon 加载时注册 `strip_ech`。
- `dns_response`：DNS 响应返回客户端前触发，按选项改写 HTTPS 资源记录。
"""

from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy.net.dns import types


class StripDnsHttpsRecords:
    """
    修改 DNS HTTPS 记录，避免客户端切到 mitmproxy 当前无法正确拦截的路径。
    """

    def load(self, loader):
        """
        addon 加载事件：注册是否移除 ECH 参数的开关。
        """
        loader.add_option(
            "strip_ech",
            bool,
            True,
            "Strip Encrypted ClientHello (ECH) data from DNS HTTPS records so that mitmproxy can generate matching certificates.",
        )

    def dns_response(self, flow: dns.DNSFlow):
        """
        DNS `dns_response` 事件：DNS 响应即将返回客户端前触发。

        处理原理：
        - ECH 参数会让客户端加密 ClientHello 中的真实 SNI，mitmproxy 难以基于
          SNI 生成匹配证书，因此在 `strip_ech` 开启时删除 HTTPS 记录里的 ECH。
        - 如果 `http3` 关闭，则从 HTTPS 记录的 ALPN 参数中删除 h3/h3-*，避免
          客户端根据 DNS 提示改用 QUIC/HTTP/3 绕过当前 HTTP/TCP 拦截链路。
        """
        assert flow.response
        if ctx.options.strip_ech:
            for answer in flow.response.answers:
                if answer.type == types.HTTPS:
                    answer.https_ech = None
        if not ctx.options.http3:
            for answer in flow.response.answers:
                if (
                    answer.type == types.HTTPS
                    and answer.https_alpn is not None
                    and any(
                        # HTTP/3 or any of the spec drafts (h3-...)?
                        a == b"h3" or a.startswith(b"h3-")
                        for a in answer.https_alpn
                    )
                ):
                    alpns = tuple(
                        a
                        for a in answer.https_alpn
                        if a != b"h3" and not a.startswith(b"h3-")
                    )
                    answer.https_alpn = alpns or None
