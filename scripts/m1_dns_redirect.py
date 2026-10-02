#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只针对悟空M1(192.168.1.54)的定向 DNS 劫持。

作用范围严格限定：只向 192.168.1.54 发送伪造 ARP 应答（声称网关 .1 在 NAS 的 MAC 上），
并从原始套接字截获该 IP 发出的 DNS 查询：
  - aircat.phicomm.com  -> 192.168.1.6（假服务器）
  - 其它域名            -> 转发给真实 DNS 并原样回给设备
不使用 ip addr 占用网关地址，因此不会影响局域网内其他任何设备。
退出时会向设备回发正确的网关 MAC，让其 ARP 缓存恢复。
"""
import os
import signal
import socket
import struct
import sys
import threading
import time

IFACE = os.environ.get("IFACE", "eth0")
M1_IP = os.environ.get("M1_IP", "192.168.1.54")
M1_MAC_HEX = os.environ.get("M1_MAC", "aabbccddeeff")
GW_IP = os.environ.get("GW_IP", "192.168.1.1")
FAKE_IP = os.environ.get("FAKE_IP", "192.168.1.6")
TARGET = os.environ.get("TARGET_DOMAIN", "aircat.phicomm.com").lower().encode()
UPSTREAM_DNS = os.environ.get("UPSTREAM_DNS", "192.168.1.1")

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

running = True


def log(msg):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def mac_bytes(hexstr):
    return bytes.fromhex(hexstr.replace(":", "").replace("-", ""))


def ip_bytes(s):
    return socket.inet_aton(s)


def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return mac_bytes(f.read().strip())


NAS_MAC = get_iface_mac(IFACE)
M1_MAC = mac_bytes(M1_MAC_HEX)


def real_gw_mac():
    try:
        out = os.popen(f"ip neigh show {GW_IP}").read().strip()
        for tok in out.split():
            if ":" in tok and len(tok) == 17:
                return mac_bytes(tok)
    except Exception:
        pass
    return None


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def attach_bpf(sock, m1_ip: str) -> bool:
    """只让内核把「来自 M1 的 UDP」交给用户态，其余直接丢。

    不加过滤器时，raw socket 会收到网卡上所有帧再由 Python 解析 ——
    在主网卡上就是整台机器的流量，实测占 2.8~3.8% 单核。
    加上之后 TCP（占大头）在内核里就被丢掉了。

    帧布局（无 VLAN 标签）：
        [0:14]  以太网头
        [14:34] IP 头
        偏移 23 = IP 协议号（17 = UDP）
        偏移 26 = 源 IP

    返回 False 表示挂载失败（调用方继续运行，只是费点 CPU）。
    """
    try:
        import ctypes
        import socket as _socket
        import struct as _struct

        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                        ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort),
                        ("filter", ctypes.POINTER(SockFilter))]

        LD_B_ABS = 0x30      # ldb [k]
        LD_W_ABS = 0x20      # ld  [k]
        JEQ_K = 0x15         # jeq #k, jt, jf
        RET_K = 0x06         # ret #k

        # 包数据按大端解释，常量也要按大端取
        m1_be = _struct.unpack("!I", _socket.inet_aton(m1_ip))[0]

        prog = [
            SockFilter(LD_B_ABS, 0, 0, 23),      # 0: ldb [23]  -> ip->ip_p
            SockFilter(JEQ_K, 0, 3, 17),         # 1: 非 UDP -> 跳到 5（丢）
            SockFilter(LD_W_ABS, 0, 0, 26),      # 2: ld  [26]  -> ip->ip_src
            SockFilter(JEQ_K, 0, 1, m1_be),      # 3: 非 M1  -> 跳到 5（丢）
            SockFilter(RET_K, 0, 0, 0x40000),    # 4: ret 262144（放行）
            SockFilter(RET_K, 0, 0, 0),          # 5: ret 0（丢）
        ]
        arr = (SockFilter * len(prog))(*prog)
        fprog = SockFprog(len(prog), ctypes.cast(arr, ctypes.POINTER(SockFilter)))
        SO_ATTACH_FILTER = 26
        # Python 的 setsockopt 只收 3 个参数：把结构体序列化成 bytes 传进去
        sock.setsockopt(1, SO_ATTACH_FILTER,
                        ctypes.string_at(ctypes.byref(fprog), ctypes.sizeof(fprog)))
        return True
    except Exception as e:  # noqa: BLE001
        log(f"BPF 过滤器挂载失败（继续不过滤，只影响 CPU）: {e}")
        return False


raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
raw.bind((IFACE, 0))
if attach_bpf(raw, M1_IP):
    log(f"BPF 过滤器已挂载：内核只放行来自 {M1_IP} 的 UDP")
raw_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
raw_send.bind((IFACE, 0))


def send_arp_reply(claimed_ip: str, claimed_mac: bytes, to_mac: bytes, to_ip: str):
    eth = to_mac + claimed_mac + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH", 1, ETH_P_IP, 6, 4, 2
    ) + claimed_mac + ip_bytes(claimed_ip) + to_mac + ip_bytes(to_ip)
    raw_send.send(eth + arp)


def arp_spoof_loop():
    n = 0
    while running:
        send_arp_reply(GW_IP, NAS_MAC, M1_MAC, M1_IP)
        n += 1
        if n == 1 or n % 20 == 0:
            log(f"ARP spoof sent x{n} ({GW_IP} -> {NAS_MAC.hex()} toward {M1_IP})")
        time.sleep(1.5)


def build_udp_ip_frame(src_ip, dst_ip, src_port, dst_port, payload):
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 17, udp_len)
    csum = checksum(pseudo + udp_hdr + payload) or 0xFFFF
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, csum) + payload
    total = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0, ip_bytes(src_ip), ip_bytes(dst_ip)
    )
    ip_hdr = ip_hdr[:10] + struct.pack("!H", checksum(ip_hdr)) + ip_hdr[12:]
    eth = M1_MAC + NAS_MAC + struct.pack("!H", ETH_P_IP)
    return eth + ip_hdr + udp


def parse_question(dns: bytes):
    """返回 (qname_lower, qtype, qclass, offset_after_question)"""
    i = 12
    labels = []
    while i < len(dns):
        l = dns[i]
        if l == 0:
            i += 1
            break
        if l & 0xC0:  # 压缩指针，问题段不该出现
            return None, None, None, None
        labels.append(dns[i + 1:i + 1 + l])
        i += 1 + l
    if i + 4 > len(dns):
        return None, None, None, None
    qtype, qclass = struct.unpack("!HH", dns[i:i + 4])
    return b".".join(labels).lower(), qtype, qclass, i + 4


def build_dns_reply(query: bytes, qname: bytes, qtype: int, end: int):
    tid = query[:2]
    question = query[12:end]
    if qname == TARGET and qtype == 1:  # A
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes(FAKE_IP)
        return tid + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + question + answer
    # 其它类型（含 AAAA）：NOERROR 但无答案，让设备回退到 A
    return tid + b"\x81\x80" + struct.pack("!HHHH", 1, 0, 0, 0) + question


def forward_query(query: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(query, (UPSTREAM_DNS, 53))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()


def handle_dns(src_port: int, payload: bytes, queried_dns: str):
    """queried_dns 是设备实际发往的 DNS 服务器 IP。

    设备的嵌入式 DNS 客户端只接受「源 IP == 自己发往的那个服务器」的应答，
    所以伪造应答的源 IP 必须用 queried_dns，不能用网关地址。
    """
    if len(payload) < 12:
        return
    qname, qtype, qclass, end = parse_question(payload)
    if qname is None:
        return
    log(f"DNS {queried_dns} <- M1: {qname.decode(errors='replace')} type={qtype} (port {src_port})")
    try:
        if qname == TARGET:
            reply = build_dns_reply(payload, qname, qtype, end)
            log(f"  -> 本地应答 {FAKE_IP} (源IP伪装为 {queried_dns})" if qtype == 1
                else "  -> 空应答(让设备回退 A)")
        else:
            reply = forward_query(payload)
            log(f"  -> 转发上游 {UPSTREAM_DNS} ({len(reply)}B)")
    except Exception as e:  # noqa: BLE001
        log(f"  !! build/forward failed: {e}")
        return
    frame = build_udp_ip_frame(queried_dns, M1_IP, 53, src_port, reply)
    raw_send.send(frame)


def sniff_loop():
    log(f"sniffing DNS on {IFACE}, watching {M1_IP}")
    while running:
        try:
            pkt = raw.recv(65535)
        except OSError:
            if running:
                time.sleep(0.2)
            continue
        if len(pkt) < 34:
            continue
        if pkt[12:14] != b"\x08\x00":
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 17:  # UDP
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])
        if src_ip != M1_IP:
            continue
        udp_off = 14 + ihl
        if len(pkt) < udp_off + 8:
            continue
        src_port, dst_port, ulen, _ = struct.unpack("!HHHH", pkt[udp_off:udp_off + 8])
        if dst_port != 53:
            continue
        payload = pkt[udp_off + 8:udp_off + min(ulen, len(pkt) - udp_off)]
        try:
            handle_dns(src_port, payload, dst_ip)
        except Exception as e:  # noqa: BLE001
            log(f"handle_dns error: {e}")


def shutdown(*_):
    global running
    log("shutting down; restoring ARP for the device")
    running = False
    gw_mac = real_gw_mac()
    if gw_mac:
        for _ in range(5):
            send_arp_reply(GW_IP, gw_mac, M1_MAC, M1_IP)
            time.sleep(0.3)
        log(f"restored: {GW_IP} -> {gw_mac.hex()}")
    else:
        log("could not determine real gateway MAC; ARP entry will expire on its own")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log(f"=== zM1 dns redirect start: iface={IFACE} nas_mac={NAS_MAC.hex()} ===")
    log(f"target={TARGET.decode()} -> {FAKE_IP}; victim={M1_IP}")
    threading.Thread(target=arp_spoof_loop, daemon=True).start()
    sniff_loop()
