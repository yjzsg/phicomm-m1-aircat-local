#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""假的斐讯云端 —— 应答悟空M1 的激活请求。

为什么需要
----------
M1 启动后会调 `GET https://aircat.phicomm.com/device/active?mac=<mac>&productId=1`
做激活。实测：

  - DNS 返回 NXDOMAIN  -> 设备能上报，但会反复重试，约 14 小时后卡死
  - TLS 失败           -> 设备每秒重试 1~2 次，风暴式重试
  - 返回 {"code":0}    -> 设备满意，不再重试（实测 5 分钟 0 次请求）

好消息：设备不校验证书（自签证书握手能成功），所以可以完整伪造。

用法
----
监听 0.0.0.0:<PORT>，用 <CERT>/<KEY> 做 TLS。需要外部把设备的
<别名IP>:443 DNAT 到本端口（见 systemd 单元 m1-fake-cloud）。

只用标准库。
"""

import http.server
import json
import os
import ssl
import sys
import time

PORT = int(os.environ.get("FAKE_CLOUD_PORT", "9443"))
CERT = os.environ.get("FAKE_CLOUD_CERT", "/data/cloud.crt")
KEY = os.environ.get("FAKE_CLOUD_KEY", "/data/cloud.key")
# 应答体。{"code":0,...} 是实测能让设备满意的格式。
RESPONSE = os.environ.get("FAKE_CLOUD_RESPONSE", '{"code":0,"message":"success"}')


def log(msg):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status=200, body=None):
        body = body if body is not None else RESPONSE
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if "/device/active" in self.path:
            log(f"激活请求 {self.path} -> {RESPONSE[:50]}")
            self._reply(200)
        else:
            log(f"未知请求 {self.path} -> 404")
            self._reply(404, '{"code":1,"message":"not found"}')

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        log(f"POST {self.path} body={body[:120]!r}")
        self._reply(200)

    def log_message(self, fmt, *args):  # 静音默认日志，用自己的
        pass


def main():
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        log(f"!! 证书不存在: {CERT} / {KEY}")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log(f"=== 假云端启动 :{PORT} 应答 {RESPONSE[:50]} ===")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
