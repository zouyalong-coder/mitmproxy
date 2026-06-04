"""
启动隔离浏览器并自动配置代理的命令型 addon。

触发点：
- `browser.start` 命令：用户显式启动 Chrome/Chromium 或 Firefox。
- `done`：mitmproxy 关闭时清理浏览器进程和临时 profile。
- 本 addon 不监听网络生命周期事件。
"""

import logging
import shutil
import subprocess
import tempfile

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy.log import ALERT


def find_executable_cmd(*search_paths) -> list[str] | None:
    """
    在系统 PATH 中查找可执行程序，并返回可用于启动的命令参数。
    """
    for browser in search_paths:
        if shutil.which(browser):
            return [browser]

    return None


def find_flatpak_cmd(*search_paths) -> list[str] | None:
    """
    检测 Flatpak 应用是否存在，并返回对应启动命令。
    """
    if shutil.which("flatpak"):
        for browser in search_paths:
            if (
                subprocess.run(
                    ["flatpak", "info", browser],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode
                == 0
            ):
                return ["flatpak", "run", "-p", browser]

    return None


class Browser:
    """
    管理由 mitmproxy 启动的浏览器进程和临时用户数据目录。
    """
    browser: list[subprocess.Popen] = []
    tdir: list[tempfile.TemporaryDirectory] = []

    @command.command("browser.start")
    def start(self, browser: str = "chrome") -> None:
        """
        `browser.start` 命令：启动指定浏览器并指向当前 mitmproxy 监听地址。
        """
        if len(self.browser) > 0:
            logging.log(ALERT, "Starting additional browser")

        if browser in ("chrome", "chromium"):
            self.launch_chrome()
        elif browser == "firefox":
            self.launch_firefox()
        else:
            logging.log(ALERT, "Invalid browser name.")

    def launch_chrome(self) -> None:
        """
        Start an isolated instance of Chrome that points to the currently
        running proxy.
        
        中文说明：创建独立 Chrome profile，并通过 `--proxy-server` 指向当前
        mitmproxy 实例。
        """
        cmd = find_executable_cmd(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            # https://stackoverflow.com/questions/40674914/google-chrome-path-in-windows-10
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Application\chrome.exe",
            # Linux binary names from Python's webbrowser module.
            "google-chrome",
            "google-chrome-stable",
            "chrome",
            "chromium",
            "chromium-browser",
            "google-chrome-unstable",
        ) or find_flatpak_cmd(
            "com.google.Chrome",
            "org.chromium.Chromium",
            "com.github.Eloston.UngoogledChromium",
            "com.google.ChromeDev",
        )

        if not cmd:
            logging.log(
                ALERT, "Your platform is not supported yet - please submit a patch."
            )
            return

        tdir = tempfile.TemporaryDirectory()
        self.tdir.append(tdir)
        self.browser.append(
            subprocess.Popen(
                [
                    *cmd,
                    "--user-data-dir=%s" % str(tdir.name),
                    "--proxy-server={}:{}".format(
                        ctx.options.listen_host or "127.0.0.1",
                        ctx.options.listen_port or "8080",
                    ),
                    "--disable-fre",
                    "--no-default-browser-check",
                    "--no-first-run",
                    "--disable-extensions",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )

    def launch_firefox(self) -> None:
        """
        Start an isolated instance of Firefox that points to the currently
        running proxy.
        
        中文说明：创建独立 Firefox profile，通过 prefs.js 配置 HTTP/HTTPS 代理，
        并关闭若干联网和遥测功能以减少启动噪声。
        """
        cmd = find_executable_cmd(
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            "firefox",
            "mozilla-firefox",
            "mozilla",
        ) or find_flatpak_cmd("org.mozilla.firefox")

        if not cmd:
            logging.log(
                ALERT, "Your platform is not supported yet - please submit a patch."
            )
            return

        host = ctx.options.listen_host or "127.0.0.1"
        port = ctx.options.listen_port or 8080
        prefs = [
            'user_pref("datareporting.policy.firstRunURL", "");',
            'user_pref("network.proxy.type", 1);',
            'user_pref("network.proxy.share_proxy_settings", true);',
            'user_pref("datareporting.healthreport.uploadEnabled", false);',
            'user_pref("app.normandy.enabled", false);',
            'user_pref("app.update.auto", false);',
            'user_pref("app.update.enabled", false);',
            'user_pref("app.update.autoInstallEnabled", false);',
            'user_pref("app.shield.optoutstudies.enabled", false);'
            'user_pref("extensions.blocklist.enabled", false);',
            'user_pref("browser.safebrowsing.downloads.remote.enabled", false);',
            'user_pref("browser.region.network.url", "");',
            'user_pref("browser.region.update.enabled", false);',
            'user_pref("browser.region.local-geocoding", false);',
            'user_pref("extensions.pocket.enabled", false);',
            'user_pref("network.captive-portal-service.enabled", false);',
            'user_pref("network.connectivity-service.enabled", false);',
            'user_pref("toolkit.telemetry.server", "");',
            'user_pref("dom.push.serverURL", "");',
            'user_pref("services.settings.enabled", false);',
            'user_pref("browser.newtab.preload", false);',
            'user_pref("browser.safebrowsing.provider.google4.updateURL", "");',
            'user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");',
            'user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);',
            'user_pref("browser.newtabpage.activity-stream.default.sites", "");',
            'user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);',
            'user_pref("browser.bookmarks.restore_default_bookmarks", false);',
            'user_pref("browser.bookmarks.file", "");',
        ]
        for service in ("http", "ssl"):
            prefs += [
                f'user_pref("network.proxy.{service}", "{host}");',
                f'user_pref("network.proxy.{service}_port", {port});',
            ]

        tdir = tempfile.TemporaryDirectory()

        with open(tdir.name + "/prefs.js", "w") as file:
            file.writelines(prefs)

        self.tdir.append(tdir)
        self.browser.append(
            subprocess.Popen(
                [
                    *cmd,
                    "--profile",
                    str(tdir.name),
                    "--new-window",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )

    def done(self):
        """
        `done` 事件：mitmproxy 关闭时触发，终止浏览器进程并删除临时 profile。
        """
        for browser in self.browser:
            browser.kill()
        for tdir in self.tdir:
            tdir.cleanup()
        self.browser = []
        self.tdir = []
