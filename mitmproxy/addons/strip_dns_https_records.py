"""
`mitmproxy.addons.strip_dns_https_records` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
"""

from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy.net.dns import types


class StripDnsHttpsRecords:
    """
    `strip_dns_https_records` addon 的主要类或辅助类，封装该功能的状态和处理逻辑。
    """
    def load(self, loader):
        """
        注册该 addon 暴露的配置项、命令或启动期资源。
        """
        loader.add_option(
            "strip_ech",
            bool,
            True,
            "Strip Encrypted ClientHello (ECH) data from DNS HTTPS records so that mitmproxy can generate matching certificates.",
        )

    def dns_response(self, flow: dns.DNSFlow):
        """
        处理 DNS 响应事件。
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
