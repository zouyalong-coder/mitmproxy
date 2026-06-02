"""
`mitmproxy.addons.onboardingapp` 模块的中文说明：提供对应内置 addon 的注册、命令和 hook 处理逻辑。
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
    `onboardingapp` addon 中的函数，用于处理 `index` 相关逻辑。
    """
    return render_template("index.html")


@app.route("/cert/pem")
def pem():
    """
    `onboardingapp` addon 中的函数，用于处理 `pem` 相关逻辑。
    """
    return read_cert("pem", "application/x-x509-ca-cert")


@app.route("/cert/p12")
def p12():
    """
    `onboardingapp` addon 中的函数，用于处理 `p12` 相关逻辑。
    """
    return read_cert("p12", "application/x-pkcs12")


@app.route("/cert/cer")
def cer():
    """
    `onboardingapp` addon 中的函数，用于处理 `cer` 相关逻辑。
    """
    return read_cert("cer", "application/x-x509-ca-cert")


@app.route("/cert/magisk")
def magisk():
    """
    `onboardingapp` addon 中的函数，用于处理 `magisk` 相关逻辑。
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
    `onboardingapp` addon 中的函数，用于处理 `read cert` 相关逻辑。
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
