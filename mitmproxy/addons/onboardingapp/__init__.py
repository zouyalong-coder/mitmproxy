"""
mitm.it 引导页使用的 Flask 应用。

触发点：
- 这些函数不是 mitmproxy hook，而是 Flask route handler。
- `Onboarding` addon 通过 WSGIApp 在 HTTP `request` 事件中把匹配 host 的请求转交给这里。
"""

import os

from flask import Flask
from flask import render_template

from mitmproxy.options import CONF_BASENAME
from mitmproxy.options import CONF_DIR
from mitmproxy.utils.magisk import write_magisk_module

app = Flask(__name__)
# will be overridden in the addon, setting this here so that the Flask app can be run standalone.
app.config["CONFDIR"] = CONF_DIR


@app.route("/")
def index():
    """
    Flask `/` 路由：返回证书安装引导首页。
    """
    return render_template("index.html")


@app.route("/cert/pem")
def pem():
    """
    Flask `/cert/pem` 路由：下载 PEM 格式 CA 证书。
    """
    return read_cert("pem", "application/x-x509-ca-cert")


@app.route("/cert/p12")
def p12():
    """
    Flask `/cert/p12` 路由：下载 PKCS#12 格式 CA 证书。
    """
    return read_cert("p12", "application/x-pkcs12")


@app.route("/cert/cer")
def cer():
    """
    Flask `/cert/cer` 路由：下载 CER 格式 CA 证书。
    """
    return read_cert("cer", "application/x-x509-ca-cert")


@app.route("/cert/magisk")
def magisk():
    """
    Flask `/cert/magisk` 路由：生成并下载 Android Magisk 证书模块。
    """
    filename = CONF_BASENAME + f"-magisk-module.zip"
    p = os.path.join(app.config["CONFDIR"], filename)
    p = os.path.expanduser(p)

    if not os.path.exists(p):
        write_magisk_module(p)

    with open(p, "rb") as f:
        cert = f.read()

    return cert, {
        "Content-Type": "application/zip",
        "Content-Disposition": f"attachment; {filename=!s}",
    }


def read_cert(ext, content_type):
    """
    从配置目录读取指定扩展名的 CA 证书，并返回下载响应头。
    """
    filename = CONF_BASENAME + f"-ca-cert.{ext}"
    p = os.path.join(app.config["CONFDIR"], filename)
    p = os.path.expanduser(p)
    with open(p, "rb") as f:
        cert = f.read()

    return cert, {
        "Content-Type": content_type,
        "Content-Disposition": f"attachment; {filename=!s}",
    }
