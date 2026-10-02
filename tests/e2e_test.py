#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端自测：不需要真实设备，用模拟客户端验证服务器行为。

跑法（需要能连到 MQTT broker）：

    MQTT_PASS=你的密码 python3 tests/e2e_test.py

它会：
  1. 用测试端口 19000、测试主题启动 ../scripts/aircat_server.py
  2. 模拟设备连上去，发一帧真实格式的传感器上报
  3. 检查 MQTT 上出现解析好的数据
  4. 往 set 主题发亮度指令，检查设备收到的帧长度字节对不对

用测试端口/测试主题是为了能和既有部署并存，不影响线上设备。
"""
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "..", "scripts", "aircat_server.py")
PORT = int(os.environ.get("TEST_PORT", "19000"))
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = os.environ.get("MQTT_PORT", "1883")
MQTT_USER = os.environ.get("MQTT_USER", "homeassistant")
MQTT_PASS = os.environ.get("MQTT_PASS", "")
MAC = bytes.fromhex(os.environ.get("TEST_MAC", "aabbccddeeff"))
END = b"\xff#END#"

TOPIC_SENSOR = "testrepo/zm1/sensor"
TOPIC_STATE = "testrepo/zm1/state"
TOPIC_SET = "testrepo/zm1/set"

# 用 mosquitto 镜像里的客户端，省得装依赖
DOCKER_MQTT = ["docker", "run", "--rm", "--network", "host", "eclipse-mosquitto:2"]

ok_all = True


def check(name, cond, detail=""):
    global ok_all
    if not cond:
        ok_all = False
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def dev_frame(json_str, msg_type=4):
    """设备方向的封帧：Length = 3 + len(JSON)"""
    j = json_str.encode()
    hdr = (b"\xaa" + b"\x00" * 16 + b"\x00" + MAC + b"\x00"
           + bytes([3 + len(j)]) + b"\x00\x00" + bytes([msg_type]))
    return hdr + j + END


def drain(sock, buf, seconds, stop_when=None):
    """读若干秒，按 \\xff#END# 切出完整帧"""
    frames = []
    deadline = time.time() + seconds
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while b"\xff#END#" in buf:
            f, buf = buf.split(b"\xff#END#", 1)
            frames.append(f + b"\xff#END#")
        if stop_when and any(stop_when(f) for f in frames):
            break
    return frames, buf


def main():
    print("=== 1) 启动服务器（测试端口 %d）===" % PORT)
    env = dict(os.environ)
    env.update({
        "AIRCAT_PORT": str(PORT),
        "DATA_DIR": os.path.join(HERE, "_test_data"),
        "MQTT_HOST": MQTT_HOST,
        "MQTT_PORT": MQTT_PORT,
        "MQTT_USER": MQTT_USER,
        "MQTT_PASS": MQTT_PASS,
        "MQTT_TOPIC_HA": TOPIC_SENSOR,
        "MQTT_TOPIC_STATE": TOPIC_STATE,
        "MQTT_TOPIC_SET": TOPIC_SET,
    })
    os.makedirs(env["DATA_DIR"], exist_ok=True)
    srv = subprocess.Popen([sys.executable, SERVER], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(3)
    if srv.poll() is not None:
        print("  服务器启动失败：")
        print(srv.stdout.read())
        return 1
    print(f"  已启动 pid={srv.pid}")

    sub = subprocess.Popen(
        DOCKER_MQTT + ["mosquitto_sub", "-h", MQTT_HOST, "-p", MQTT_PORT,
                       "-u", MQTT_USER, "-P", MQTT_PASS,
                       "-t", TOPIC_SENSOR, "-t", TOPIC_STATE, "-v"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(2)

    try:
        print("\n=== 2) 模拟设备连接并上报 ===")
        sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        sock.sendall(dev_frame("", msg_type=1))       # 真机会先发一帧空 JSON 状态帧
        time.sleep(0.5)
        payload = {"humidity": "55.5", "temperature": "23.4", "value": "17", "hcho": "20"}
        sock.sendall(dev_frame(json.dumps(payload), msg_type=4))
        print(f"  已发送: {payload}")
        time.sleep(3)

        print("\n=== 3) 检查 MQTT 上的数据 ===")
        sub.terminate()
        out = ""
        try:
            out = sub.communicate(timeout=5)[0] or ""
        except Exception:
            pass
        for ln in out.strip().splitlines():
            print(f"    {ln}")
        check("温度解析正确", '"temperature": "23.4"' in out)
        check("湿度解析正确", '"humidity": "55.5"' in out)
        check("PM2.5 取自 value 字段", '"PM25": "17"' in out)
        check("甲醛除以 1000", '"formaldehyde": 0.02' in out)

        print("\n=== 4) 检查服务器发来的帧 ===")
        frames, buf = drain(sock, b"", 12)
        for i, f in enumerate(frames):
            print(f"  帧{i}: 长度字节={f[24]}(0x{f[24]:02x}) 整帧={len(f)}B "
                  f"MsgType={f[27]} JSON={f[28:-6].decode('utf-8', 'replace')}")
        check("收到了服务器的报文", len(frames) > 0)
        hb = [f for f in frames if b'"type":5' in f]
        check("有心跳帧", len(hb) > 0)
        if hb:
            check("心跳 Length = 28+21+6 = 55", hb[0][24] == 55, f"实际 {hb[0][24]}")

        print("\n=== 5) 触发亮度指令 ===")
        subprocess.run(DOCKER_MQTT + ["mosquitto_pub", "-h", MQTT_HOST, "-p", MQTT_PORT,
                                      "-u", MQTT_USER, "-P", MQTT_PASS,
                                      "-t", TOPIC_SET, "-m",
                                      json.dumps({"mac": MAC.hex(), "brightness": 0})],
                       capture_output=True)
        frames2, _ = drain(sock, buf, 10, stop_when=lambda f: b"brightness" in f)
        bri = [f for f in frames2 if b"brightness" in f]
        for f in bri:
            print(f"  亮度帧: 长度字节={f[24]}(0x{f[24]:02x}) 整帧={len(f)}B "
                  f"JSON={f[28:-6].decode()}")
        check("收到亮度指令帧", len(bri) > 0)
        if bri:
            f = bri[0]
            body = f[28:-6]
            expect = 28 + len(body) + 6
            check("亮度帧 Length = 28+len(JSON)+6（关键）",
                  f[24] == expect, f"期望 {expect}，实际 {f[24]}")
            check("亮度 JSON 不含 mac 字段", b"mac" not in body, body.decode())
        sock.close()
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()
        print("\n  已停止服务器")

    print("\n" + ("=== 全部通过 ===" if ok_all else "=== 有失败项 ==="))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
