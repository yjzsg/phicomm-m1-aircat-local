#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""伪装斐讯 aircat.phicomm.com:9000 服务器（仅标准库）。

实测悟空M1原厂固件报文：28 字节头 + JSON + b'\\xff#END#'
    头布局：16字节unknown + 00 + 6字节MAC + 00 + Length + 00 00 + MsgType
服务器必须把收到的报文头原样回发（否则设备会主动断开）。
心跳 {"type":5,"status":1}；亮度 {"brightness":"25","type":2}，取 0/25/50/100。

⚠️ Length 字段的含义两个方向不一样（见 _frame_with_json 的注释）：
    设备->服务器 = 3 + len(JSON)
    服务器->设备 = 28 + len(JSON) + 6（整帧总长度）
写错长度设备会忽略指令，更糟的是解析器失步、彻底停止上报。

数据发布到 HA 已配置好的 topic：
    device/zm1/<mac>/sensor   <- 传感器
    device/zm1/<mac>/state    <- 亮度状态（响应 .../set）
"""
import json
import os
import socket
import socketserver
import threading
import time

# 监听端口 / 数据目录 / 设备 MAC —— 都可用环境变量覆盖，默认值向后兼容
LISTEN_PORT = int(os.environ.get("AIRCAT_PORT", "9000"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DEVICE_MAC_HEX = os.environ.get("M1_MAC", "aabbccddeeff")
DEVICE_MAC = bytes.fromhex(DEVICE_MAC_HEX)
LOG = os.path.join(DATA_DIR, "aircat.log")
FRAME_END = b"\xff#END#"


def _frame_with_json(json_bytes: bytes, msg_type: int = 2) -> bytes:
    """按协议组装服务器->设备报文。

    28 字节报文头 + JSON + \\xff#END#，其中头布局（来自 corbamico/phicomm-aircat-srv 源码）：
        [0:16]   unknown（16B，本机实测为 aa + 15 个 00）
        [16:24]  mac 字段 = 00 + MAC(6B) + 00
        [24]     Length
        [25:27]  Padding = 00 00
        [27]     MsgType（1=active, 2=control, 4=report）

    **Length 的含义两个方向不一样**（由仓库里的 phicomm-m1.pcap 实测反推，5 个报文集一致）：
        设备 -> 服务器：Length = 3 + len(JSON)
        服务器 -> 设备：Length = 整帧总长度 = 28 + len(JSON) + 6
    例如 brightness 25 -> 28+28+6 = 62 = 0x3e；心跳 -> 28+21+6 = 55 = 0x37。
    按 3+len(JSON) 发会让设备忽略指令（这正是之前亮度一直无效的原因）。

    调用方负责在前面拼上 23 字节（unknown + mac 字段前 7 字节），本函数返回后 5 字节 + JSON + 尾。
    """
    ln = 28 + len(json_bytes) + 6
    if ln > 255:
        raise ValueError(f"payload too long: {ln}")
    return b"\x00" + bytes([ln]) + b"\x00\x00" + bytes([msg_type]) + json_bytes + FRAME_END


HEARTBEAT_BODY = _frame_with_json(b'{"type":5,"status":1}', 2)

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "")
MQTT_PASS = os.environ.get("MQTT_PASS", "")
TOPIC_RAW = os.environ.get("MQTT_TOPIC_RAW", "aircat/raw")
TOPIC_HA = os.environ.get("MQTT_TOPIC_HA", "device/zm1/b0f89324a3ac/sensor")
TOPIC_STATE = os.environ.get("MQTT_TOPIC_STATE", "device/zm1/b0f89324a3ac/state")
TOPIC_SET = os.environ.get("MQTT_TOPIC_SET", "device/zm1/b0f89324a3ac/set")
# MQTT 客户端 id：必须唯一，否则同一 broker 上的多个实例会互相踢掉。
# 默认带上监听端口，这样自测实例（19000）不会影响线上实例（9000）。
MQTT_CLIENT_ID = os.environ.get("MQTT_CLIENT_ID", f"aircat-fake-{LISTEN_PORT}")

_log_lock = threading.Lock()
CONNS = {}          # addr -> {"sock", "header", "lock"}
_conns_lock = threading.Lock()


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with _log_lock:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


# ---------------- 最小 MQTT 客户端（发布 + 订阅） ----------------

def _enc_len(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            return bytes(out)


def _mstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return len(b).to_bytes(2, "big") + b


class MiniMQTT:
    def __init__(self, host, port, user, password, client_id):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.client_id = client_id
        self.sock = None
        self.wlock = threading.Lock()
        self.handlers = {}

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed")
            buf += chunk
        return buf

    def _read_packet(self):
        first = self._read_exact(1)[0]
        mult, value = 1, 0
        while True:
            b = self._read_exact(1)[0]
            value += (b & 0x7F) * mult
            if not (b & 0x80):
                break
            mult *= 128
        return first, self._read_exact(value) if value else b""

    def _connect(self):
        s = socket.create_connection((self.host, self.port), timeout=10)
        flags = 0x02
        payload = _mstr(self.client_id)
        if self.user:
            flags |= 0x80
            payload += _mstr(self.user)
            if self.password:
                flags |= 0x40
                payload += _mstr(self.password)
        vh = _mstr("MQTT") + bytes([4, flags]) + (60).to_bytes(2, "big")
        body = vh + payload
        s.sendall(bytes([0x10]) + _enc_len(len(body)) + body)
        s.settimeout(10)
        ack = s.recv(4)
        if len(ack) < 4 or ack[0] != 0x20 or ack[3] != 0x00:
            raise OSError(f"CONNACK failed: {ack!r}")
        self.sock = s
        s.settimeout(None)
        log(f"MQTT connected to {self.host}:{self.port}")
        for topic in self.handlers:
            self._subscribe(topic)
        threading.Thread(target=self._reader, daemon=True).start()

    def _subscribe(self, topic):
        body = (1).to_bytes(2, "big") + _mstr(topic) + b"\x00"
        self.sock.sendall(bytes([0x82]) + _enc_len(len(body)) + body)
        log(f"MQTT subscribed {topic}")

    def subscribe(self, topic, handler):
        self.handlers[topic] = handler
        if self.sock:
            self._subscribe(topic)

    def _reader(self):
        mine = self.sock
        while True:
            try:
                first, body = self._read_packet()
            except Exception as e:  # noqa: BLE001
                log(f"MQTT reader stopped: {e}")
                if self.sock is mine:
                    self.sock = None
                return
            ptype = first >> 4
            if ptype == 3 and body:
                tlen = int.from_bytes(body[:2], "big")
                topic = body[2:2 + tlen].decode("utf-8", "replace")
                rest = body[2 + tlen:]
                qos = (first >> 1) & 0x03
                if qos > 0:
                    rest = rest[2:]
                for t, h in self.handlers.items():
                    if t == topic:
                        try:
                            h(topic, rest)
                        except Exception as e:  # noqa: BLE001
                            log(f"handler error: {e}")
            elif ptype == 13:  # PINGRESP
                pass

    def publish(self, topic, payload: bytes, retain=False):
        with self.wlock:
            for attempt in (1, 2):
                try:
                    if self.sock is None:
                        self._connect()
                    body = _mstr(topic) + payload
                    hdr = 0x31 if retain else 0x30
                    self.sock.sendall(bytes([hdr]) + _enc_len(len(body)) + body)
                    return True
                except Exception as e:  # noqa: BLE001
                    log(f"MQTT publish error (attempt {attempt}): {e}")
                    try:
                        if self.sock:
                            self.sock.close()
                    except Exception:
                        pass
                    self.sock = None
                    time.sleep(1)
        return False

    def connect_now(self):
        """启动时立刻建立 MQTT 连接并订阅，避免前 20 秒收不到指令。"""
        with self.wlock:
            if self.sock is None:
                self._connect()

    def keepalive_loop(self):
        """保活 + 断线自动重连。

        以前只在 publish 时懒重连：设备一旦停止上报就没有 publish，
        MQTT 连接超时断开后订阅失效，HA 发来的 set 指令会被静默丢掉。
        这里每 20 秒主动 PINGREQ，断线则重连并重新订阅。
        """
        while True:
            time.sleep(20)
            with self.wlock:
                try:
                    if self.sock is None:
                        self._connect()          # 内部会重新订阅所有 handler
                        log("MQTT 已重连并重新订阅")
                    else:
                        self.sock.sendall(b"\xc0\x00")  # PINGREQ
                except Exception as e:  # noqa: BLE001
                    log(f"MQTT 保活失败，将重连: {e}")
                    try:
                        if self.sock:
                            self.sock.close()
                    except Exception:
                        pass
                    self.sock = None


MQTT = MiniMQTT(MQTT_HOST, MQTT_PORT, MQTT_USER, MQTT_PASS, MQTT_CLIENT_ID)


def publish(topic, obj, retain=False):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    ok = MQTT.publish(topic, data, retain)
    log(f"MQTT {'->' if ok else 'FAIL'} {topic} {obj}")


# ---------------- 亮度控制 ----------------

LEVELS = {0: 0.0, 1: 25.0, 2: 50.0, 3: 75.0, 4: 100.0}


def send_brightness(level: int):
    """设置屏幕亮度。

    level 是 HA 侧的档位 0-4（与 state 主题里的 brightness 字段同尺度），
    映射成设备要求的百分比。设备指令 JSON **不带 mac 字段**，
    与 phicomm-m1.pcap 里服务器实际发的完全一致：
        {"brightness":"25","type":2}   （整帧 62 字节，Length=0x3e）
    """
    pct = LEVELS.get(int(level), 50.0)
    body = _frame_with_json(
        json.dumps({"brightness": f"{pct:g}", "type": 2}, separators=(",", ":")).encode(),
        2,
    )
    sent = 0
    with _conns_lock:
        items = list(CONNS.items())
    for addr, c in items:
        try:
            with c["lock"]:
                c["sock"].sendall(c["header"] + body)
                # 协议文档：设备收到指令后会暂停上报，补一条心跳唤醒
                c["sock"].sendall(c["header"] + HEARTBEAT_BODY)
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"brightness send to {addr} failed: {e}")
    log(f"亮度 -> 档位 {level}（设备值 {pct:g}）已发往 {sent} 个连接")
    publish(TOPIC_STATE, {"brightness": int(level)}, retain=True)


def send_device_json(body: bytes, msg_type: int = 2, follow_heartbeat: bool = True):
    """把一段 JSON 按协议封帧发给设备（Length 自动按整帧总长度计算）。"""
    frame = _frame_with_json(body, msg_type)
    sent = 0
    with _conns_lock:
        items = list(CONNS.items())
    for addr, c in items:
        try:
            with c["lock"]:
                c["sock"].sendall(c["header"] + frame)
                if follow_heartbeat:
                    c["sock"].sendall(c["header"] + HEARTBEAT_BODY)
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"send to {addr} failed: {e}")
    log(f"DEVICE <- {body!r} (type={msg_type}) 已发往 {sent} 个连接")
    return sent


def on_set(topic, payload: bytes):
    """HA 发来的 set 指令：{"mac": ..., "brightness": 0-4}。

    HA 的 template light 用 0-4 这个尺度（与 state 主题的 brightness 字段一致），
    这里翻译成设备要的百分比指令再发。
    """
    body = payload.strip()
    if not body:
        return
    log(f"MQTT <- {topic} {body!r}")
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        log(f"set 指令解析失败: {e}")
        return
    if isinstance(d, dict) and "brightness" in d:
        try:
            send_brightness(int(d["brightness"]))
        except (TypeError, ValueError) as e:
            log(f"亮度值非法: {d['brightness']!r} ({e})")


def send_raw_command(body: bytes):
    """把任意 JSON 体按服务器->设备格式发给设备（调试用，长度自动计算）。"""
    frame = _frame_with_json(body, 2)
    sent = 0
    with _conns_lock:
        items = list(CONNS.items())
    for addr, c in items:
        try:
            with c["lock"]:
                c["sock"].sendall(c["header"] + frame)
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"raw cmd send to {addr} failed: {e}")
    log(f"RAWCMD -> {body!r} sent to {sent} conn(s)")


def on_cmd(topic, payload: bytes):
    """调试通道。

    RAWFULL:<hex>  整帧十六进制（含 23 字节报文头和 \\xff#END#），完全自定义
    RAW:<内容>      用默认 5 字节前缀 + 内容 + END
    其它            同 RAW
    """
    body = payload.strip()
    if not body:
        return
    if body.startswith(b"RAWFULL:"):
        send_full_frame(bytes.fromhex(body[8:].decode()))
    elif body.startswith(b"RAW:"):
        send_raw_frame(body[4:])
    else:
        send_raw_command(body)


def send_full_frame(frame: bytes):
    """发送完整的原始帧（调用方自行提供报文头与结束标记）。"""
    sent = 0
    with _conns_lock:
        items = list(CONNS.items())
    for addr, c in items:
        try:
            with c["lock"]:
                c["sock"].sendall(frame)
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"full frame send to {addr} failed: {e}")
    log(f"FULLFRAME -> {frame[:40].hex()}... ({len(frame)}B) sent to {sent} conn(s)")


def send_raw_frame(data: bytes):
    """发送 header + data + END（data 里自带 5 字节前缀）。"""
    frame = data + FRAME_END
    sent = 0
    with _conns_lock:
        items = list(CONNS.items())
    for addr, c in items:
        try:
            with c["lock"]:
                c["sock"].sendall(c["header"] + frame)
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"raw frame send to {addr} failed: {e}")
    log(f"RAWFRAME -> {data!r} sent to {sent} conn(s)")


# ---------------- 报文处理 ----------------

KNOWN_KEYS = {"humidity", "temperature", "value", "hcho"}
_unknown_keys = set()


def map_to_ha(d: dict) -> dict:
    """把原厂字段映射到 configuration.yaml 里已有的模板字段名。

    实测确认（2026-10-02，用户做粉尘测试）：
      value         -> PM2.5，单位 µg/m³（0/1/2 平时低值，粉尘测试时一路涨到 9）
      temperature   -> 温度 °C
      humidity      -> 湿度 %
      hcho          -> 甲醛，单位 µg/m³，需 /1000 才是 mg/m³（10 -> 0.01）
    """
    out = {}
    if "temperature" in d:
        out["temperature"] = d["temperature"]
    if "humidity" in d:
        out["humidity"] = d["humidity"]

    pm = None
    for k in ("PM25", "pm25", "pm2.5", "PM2_5"):
        if k in d:
            pm = d[k]
            break
    if pm is None and "value" in d:
        pm = d["value"]
    if pm is not None:
        out["PM25"] = pm

    if "hcho" in d:
        try:
            out["formaldehyde"] = round(float(d["hcho"]) / 1000.0, 4)
        except (TypeError, ValueError):
            out["formaldehyde"] = d["hcho"]

    # 结构变化监控：出现未知字段就告警（原厂固件字段集一直是这 4 个）
    extra = set(d) - KNOWN_KEYS
    if extra and extra != _unknown_keys:
        _unknown_keys.update(extra)
        log(f"!!! 报文出现新字段 {sorted(extra)} -> {d}")
        publish("aircat/alert", {"new_fields": sorted(extra), "sample": d}, retain=True)

    return out


def process_frame(frame: bytes, addr):
    if len(frame) < 23:
        return
    header, rest = frame[:23], frame[23:]
    with _conns_lock:
        if addr in CONNS:
            CONNS[addr]["header"] = header
    mac = header[17:23].hex()
    if header[0] != 0xAA:
        log(f"unexpected frame start {header[:3].hex()} from {addr}")
    s, e = rest.find(b"{"), rest.rfind(b"}")
    if s < 0 or e <= s:
        log(f"FRAME {addr} non-json body={rest!r}")
        return
    raw = rest[s:e + 1]
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception as ex:  # noqa: BLE001
        log(f"  json parse failed: {ex} raw={raw!r}")
        return
    if not isinstance(data, dict):
        return
    log(f"  json={data}")
    publish(TOPIC_RAW, {"mac": mac, "ts": int(time.time()), **data})
    mapped = map_to_ha(data)
    if mapped:
        publish(TOPIC_HA, mapped, retain=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        addr = self.client_address
        log(f"CONNECT from {addr}")
        self.request.settimeout(600)
        entry = {"sock": self.request, "header": b"\xaa" + b"\x00" * 16 + DEVICE_MAC,
                 "lock": threading.Lock()}
        with _conns_lock:
            CONNS[addr] = entry
        buf = b""
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    log(f"peer {addr} closed")
                    break
                buf += data
                while True:
                    j = buf.find(FRAME_END)
                    if j < 0:
                        break
                    frame = buf[:j + len(FRAME_END)]
                    buf = buf[j + len(FRAME_END):]
                    process_frame(frame, addr)
                    try:
                        with entry["lock"]:
                            self.request.sendall(frame[:23] + HEARTBEAT_BODY)
                    except Exception as e:  # noqa: BLE001
                        log(f"  heartbeat send failed: {e}")
                        return
                if len(buf) > 8192:
                    buf = buf[-1024:]
        except socket.timeout:
            log(f"peer {addr} idle timeout")
        except Exception as e:  # noqa: BLE001
            log(f"conn error {addr}: {e}")
        finally:
            with _conns_lock:
                CONNS.pop(addr, None)
            log(f"DISCONNECT {addr}")


def heartbeat_loop():
    """主动定时心跳。

    协议文档：M1 连上后先密集上报，之后如果收不到服务器反馈会明显减慢频率；
    而且发了亮度指令后设备会暂停上报，必须由服务器发心跳才会继续。
    所以不能只在「收到帧之后」才回心跳 —— 设备一停下来就永远等不到，形成死锁。
    """
    while True:
        time.sleep(10)
        with _conns_lock:
            items = list(CONNS.items())
        for addr, c in items:
            try:
                with c["lock"]:
                    c["sock"].sendall(c["header"] + HEARTBEAT_BODY)
            except Exception as e:  # noqa: BLE001
                log(f"主动心跳发给 {addr} 失败: {e}")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    log(f"=== aircat fake server starting on 0.0.0.0:{LISTEN_PORT} ===")
    log(f"MQTT {MQTT_HOST}:{MQTT_PORT} sensor={TOPIC_HA} state={TOPIC_STATE} set={TOPIC_SET}")
    MQTT.subscribe(TOPIC_SET, on_set)
    MQTT.subscribe("aircat/cmd", on_cmd)
    try:
        MQTT.connect_now()
    except Exception as e:  # noqa: BLE001
        log(f"启动时连接 MQTT 失败（保活线程会重试）: {e}")
    threading.Thread(target=MQTT.keepalive_loop, daemon=True).start()
    log("MQTT 保活线程已启动（每 20 秒，断线自动重连并重订阅）")
    # 主动心跳默认关闭：协议文档说设备收到心跳会暂停上报，
    # 每 10 秒发一次会把上报节奏从 3 秒拖到 ~10 秒，长期还可能把设备拖死。
    # 协议只要求「发完亮度指令后补一条」，那部分在 send_brightness / send_device_json 里。
    # 需要时设 HEARTBEAT_PROACTIVE=1 打开对比。
    if os.environ.get("HEARTBEAT_PROACTIVE", "0") == "1":
        threading.Thread(target=heartbeat_loop, daemon=True).start()
        log("主动心跳已启动（每 10 秒）—— 注意这会拖慢设备上报")
    else:
        log("主动心跳已关闭（只保留「收到帧后回一条」和「发完亮度指令后补一条」）")
    with Server(("0.0.0.0", LISTEN_PORT), Handler) as srv:
        srv.serve_forever()
