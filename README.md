# phicomm-m1-aircat-local

让**斐讯悟空M1 空气检测仪**（原厂固件）脱离已经死掉的官方云，在本地跑起来，并把数据接进 Home Assistant。

> Run a Phicomm Wukong M1 air detector (stock firmware) fully offline by impersonating
> the dead `aircat.phicomm.com` server. One container does both the DNS/ARP hijack and the
> fake server. See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the reverse-engineered protocol
> — especially the **direction-dependent `Length` field**, which is what makes brightness
> control actually work.

---

## 背景

悟空M1 是斐讯（Phicomm）2017 年出的空气检测仪，测温度、湿度、PM2.5、甲醛，带一块屏幕。
斐讯暴雷后 `aircat.phicomm.com` 已经 **NXDOMAIN**，设备开机后会一直连不上服务器，
WiFi 图标闪烁，屏幕停在初始化状态。

设备连的端口是 **9000**，协议是明文 TCP + JSON，**没有 TLS**。所以只要把域名解析骗到我们
这边、再写一个假服务器，设备就能完全恢复工作，数据也归自己。

> 本仓库针对**原厂固件**。如果你刷了 [zM1](https://github.com/a2633063/zm1) 等第三方固件，
> 协议完全不同（zM1 走 MQTT），不需要这套东西。

## 架构

只有一个容器（外加你本来就有的 MQTT broker）：

```
        ┌──────────────┐
        │  悟空M1      │  开机 -> 解析 aircat.phicomm.com -> 连 :9000
        │ 192.168.1.54 │
        └──────┬───────┘
               │ ① DNS 查询被拦截（ARP 欺骗把网关指向本机）
               ▼
     ┌─────────────────────────────────────┐
     │ aircat-fake（单容器）                │
     │  ├ m1_dns_redirect.py  后台          │
     │  │   只拦截 aircat.phicomm.com，     │
     │  │   其余转发真上游                  │
     │  └ aircat_server.py    前台          │
     │      伪装 :9000，收报文 -> MQTT      │
     └──────────────┬──────────────────────┘
                    │ ② MQTT
                    ▼
          ┌───────────────────┐
          │ Home Assistant    │  传感器 + 亮度灯 + 停更告警
          └───────────────────┘
```

**为什么两个进程放一个容器**：DNS 劫持需要 `NET_RAW`/`NET_ADMIN`，独立容器更"干净"，
但这个容器只监听内网 :9000、跑的是自己的代码、不对外暴露，权衡下来少一个容器更省心。
如果你更看重隔离，把 `m1_dns_redirect.py` 拆成独立 service 即可（环境变量原样搬过去）。

## 目录

```
docker-compose.yml                          一个 service，一条命令起全套
scripts/aircat_server.py                    假 aircat 服务器（纯标准库，自带极简 MQTT 客户端）
scripts/m1_dns_redirect.py                  定向 ARP + DNS 劫持，只针对一台设备
data/                                       运行时产物（aircat.log），已在 .gitignore 里
homeassistant/configuration-snippet.yaml    HA 的传感器 + 屏幕亮度灯 + 停更告警
docs/PROTOCOL.md                            逆向出来的协议细节
tests/e2e_test.py                           端到端自测，不需要真实设备
```

## 部署

### 0. 前置

- 一台 24 小时开机的 Linux 机器（NAS / 树莓派 / 软路由都行）
- Docker + Docker Compose
- 一个 MQTT broker（这里假设和 Home Assistant 用同一个）
- 悟空M1 和这台机器在**同一个二层网络**里（ARP 劫持需要）

### 1. 找到设备的 MAC 和 IP

路由器 DHCP 客户端列表里找 OUI 为 **`b0:f8:93`**（MXCHIP/庆科 WiFi 模块）的设备。

### 2. 改配置

```bash
git clone https://github.com/yjzsg/phicomm-m1-aircat-local.git
cd phicomm-m1-aircat-local
ip -br link                    # 看连局域网的网卡名，填到 IFACE
vim docker-compose.yml         # 把 CHANGE_ME / aabbccddeeff / eth0 / 192.168.1. 全换掉
```

| 位置 | 改成 |
|---|---|
| `MQTT_PASS` | 你的 MQTT 密码 |
| `aabbccddeeff`（四处） | 你设备的 MAC |
| `IFACE` | 服务器上连局域网的网卡名 |
| `M1_IP` / `GW_IP` / `FAKE_IP` | 设备 IP / 网关 IP / 本机 IP |

### 3. 启动

```bash
docker compose up -d
docker compose logs -f
```

日志里应该同时看到两种输出：

```
[dns] 2026-.. === zM1 dns redirect start: iface=eth0 ...
2026-.. === aircat fake server starting on 0.0.0.0:9000 ===
```

### 4. 给 M1 断电重启

它开机后会解析到我们的服务器并开始上报，日志里应该每 3 秒左右出现一条 `json={...}`：

```
[dns] DNS 223.5.5.5 <- M1: aircat.phicomm.com type=1
[dns]   -> 本地应答 192.168.1.6
2026-.. CONNECT from ('192.168.1.54', 37930)
2026-..   json={'humidity': '55.5', 'temperature': '23.4', ...}
```

### 5. 接入 Home Assistant

把 `homeassistant/configuration-snippet.yaml` 里的内容并入 HA 的 `configuration.yaml`，
把 `aabbccddeeff` 全部换成你的 MAC，重启 HA。

得到 5 个实体（温度 / 湿度 / PM2.5 / 甲醛 / 屏幕亮度），外加一条数据停更告警自动化。

### 6. 自测（可选）

不需要真实设备，用模拟客户端验证服务器行为：

```bash
MQTT_PASS=你的密码 python3 tests/e2e_test.py
```

它用测试端口 19000 + `testrepo/` 前缀的主题，不会干扰线上设备。

## 协议要点

完整版见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。最容易踩的一个坑：

**`Length` 字段的含义，两个方向不一样。**

| 方向 | Length |
|---|---|
| 设备 → 服务器 | `3 + len(JSON)` |
| **服务器 → 设备** | **整帧总长度 = 28 + len(JSON) + 6** |

例：亮度指令 `{"brightness":"25","type":2}`（JSON 28 字节）
- 设备方向会写 `3+28 = 31`
- 但服务器必须写 `28+28+6 = 62 = 0x3e`

按 `3+len` 发过去，设备会**忽略指令**；更糟的是长度写错会让设备**解析器失步**，
表现为 TCP 连接还在但彻底停止上报（详见「故障处理」）。

这个结论不是猜的，是用 [corbamico/phicomm-aircat-srv](https://github.com/corbamico/phicomm-aircat-srv)
仓库里的 `docs/misc/phicomm-m1.pcap` 反推的，5 个报文集全部吻合：

```
brightness 25  -> 28+28+6 = 62 = 0x3e
brightness 0   -> 28+27+6 = 61 = 0x3d
brightness 100 -> 28+29+6 = 63 = 0x3f
心跳            -> 28+21+6 = 55 = 0x37
sleep 配置     -> 28+56+6 = 90 = 0x5a
```

## 屏幕亮度

```json
{"brightness":"25","type":2}
```

取值 **0 / 25 / 50 / 100**（`0` = 关屏）。注意：

- 服务器发给设备的亮度指令里**不带 `mac` 字段**
- 设备收到亮度指令后不会回 ACK，所以**只能靠肉眼确认**
- 报文头里的 unknown 字段直接沿用设备发来的即可（实测本机设备是全 0）

## 故障处理

### 设备停止上报（最常见的坑）

**现象**：`ss -tn | grep 9000` 显示 TCP 连接还在，但日志里不再有 `json=` 帧。

**原因**：给设备发过**长度字段错误**的报文，固件解析器失步了。
这是全局状态，重连 TCP 不会复位。

**处理**：**给 M1 断电重启**。

配置里的「数据停更告警」自动化就是为这个场景准备的 —— 超过 10 分钟没数据会发 HA 通知。
它用的是 HA 实体自带的 `last_updated`，不需要额外容器。

### WiFi 图标一直闪

说明设备还没连上服务器。检查：
1. 容器是否在跑（DNS 劫持停了设备就解析不到域名）
2. `IFACE` 填对了没有
3. 设备和服务器是否真在同一网段

### 设备上报越来越慢，最后停掉

**现象**：上报间隔从 3 秒慢慢退化（5 秒、10 秒…），最后完全停住，
但 `ss -tn | grep 9000` 显示 TCP 连接还在（`Send-Q` 有积压 —— 设备不再读自己的 socket）。

**原因**：协议文档说设备**收到心跳就会暂停上报**。如果服务器频繁主动发心跳，
设备就被反复打断，间隔被拖长，长期可能彻底卡死（只能断电重启）。

**本仓库的处理**：主动心跳默认**关闭**（`HEARTBEAT_PROACTIVE=0`），只保留协议要求的两种：
- 收到设备帧后回一条
- 发完亮度指令后补一条（用于唤醒）

需要对比时设 `HEARTBEAT_PROACTIVE=1` 打开。

### 日志里出现 `MQTT reader stopped`

正常，那是 broker 重连。脚本自带保活线程（每 20 秒 PINGREQ + 断线重订阅）。
但如果**频繁**出现，检查是不是有另一个实例用了同一个 `MQTT_CLIENT_ID` ——
同 id 会让 broker 互相踢连接，发布落在重连空窗期会丢消息。

## 环境变量

全部有合理默认值，只有部署相关的需要改：

| 变量 | 默认 | 说明 |
|---|---|---|
| `AIRCAT_PORT` | `9000` | 监听端口（改这个可以并存多实例/自测） |
| `DATA_DIR` | `/data` | 日志目录 |
| `M1_MAC` | `aabbccddeeff` | 设备 MAC，用于拼报文头 |
| `MQTT_CLIENT_ID` | `aircat-fake-<端口>` | MQTT 客户端 id，**必须唯一** |
| `MQTT_HOST/PORT/USER/PASS` | — | broker 连接 |
| `MQTT_TOPIC_HA/STATE/SET/RAW` | — | 主题 |
| `IFACE` / `M1_IP` / `GW_IP` / `FAKE_IP` / `UPSTREAM_DNS` | — | DNS 劫持相关 |
| `TARGET_DOMAIN` | `aircat.phicomm.com` | 要拦截的域名 |

## 已知限制

- **只支持单台设备**：ARP/DNS 劫持只针对一个 IP
- **ARP 劫持需要二层可达**：跨网段、AP 隔离的环境用不了
- **屏幕亮度无法读取**：设备从不上报当前亮度，HA 里的状态是「我们发过什么就记什么」
- **甲醛单位**：设备原始值是 `hcho/1000`，这里按 mg/m³ 上报
- **raw socket 抓包有 CPU 开销，但已用 BPF 压到最低**：AF_PACKET 会把网卡上所有帧
  复制给用户态，在主网卡上意味着整机流量都要过一遍 Python —— 实测 2.8~3.8% 单核。
  脚本启动时会挂一个 BPF 过滤器，让内核只放行「来自 M1 的 UDP」，TCP 占的大头在内核
  里就丢了，实测降到 **0.02~0.2%**。挂载失败会自动回退到不过滤（只费 CPU，不影响功能）

## 参考

- [corbamico/phicomm-aircat-srv](https://github.com/corbamico/phicomm-aircat-srv) —— Go/Rust/C# 的服务器实现，仓库里有真实抓包 `phicomm-m1.pcap`，本项目的协议结论大量参考它
- [a2633063/zM1](https://github.com/a2633063/zM1) —— 第三方固件（协议不同，走 MQTT）

## License

MIT

---

## 假云端：应答设备的激活请求（重要）

M1 启动后会调用官方接口做「激活」：

```
GET https://aircat.phicomm.com/device/active?mac=<设备MAC>&productId=1
```

**实测三种应答的后果差别很大**：

| 应答 | 设备行为 |
|---|---|
| DNS 返回 NXDOMAIN | 能上报数据，但反复重试，**约 14 小时后卡死**（需要断电才能恢复） |
| TLS 握手失败 | **每秒重试 1~2 次**，风暴式重试 |
| **返回 `{"code":0}`** | **不再重试**（实测 5 分钟内 0 次请求） |

**好消息：设备不校验证书。** 自签证书的 TLS 握手能成功，所以可以完整伪造这个接口。

### 部署

本仓库的 `scripts/m1_fake_cloud.py` 就是这个小 HTTPS 服务，compose 里已经和
假服务器一起启动（日志前缀 `[cloud]`）。

还需要两件外部配置：

**① 生成自签证书**（设备不校验，随便签）

```bash
cd <部署目录>/data
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout cloud.key -out cloud.crt -subj "/CN=aircat.phicomm.com"
```

**② 给假云端一个独立 IP**

设备的 DNS 被我们接管后，`aircat.phicomm.com` 要指向**一个能跑我们自己 HTTPS 服务的地址**。
但本机的 443 端口通常被别的服务（NAS 的 nginx、路由器管理页等）占着，
所以用一个**独立的别名 IP**：

```
别名 IP        192.168.123.250   （可换成你网段里任一空闲 IP）
DNAT           192.168.123.250:443 → 本机:9443
DNS 应答       aircat.phicomm.com → 192.168.123.250
```

仓库里的 `systemd/` 目录提供了现成脚本和单元：

```bash
sudo cp systemd/m1-fake-cloud-net.sh /usr/local/bin/
sudo chmod 755 /usr/local/bin/m1-fake-cloud-net.sh
sudo cp systemd/m1-fake-cloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now m1-fake-cloud
```

**改 IP 用环境变量**（编辑单元里的 `Environment=`）：

```ini
Environment=ALIAS_IP=192.168.123.250
Environment=IFACE_NAME=enxc84d44294124
Environment=TARGET_IP=192.168.123.6
Environment=FAKE_CLOUD_PORT=9443
```

### 验证

从**另一台机器**（不能是部署机本身，因为本机流量不走 DNAT）：

```bash
curl -sk "https://192.168.123.250/device/active?mac=<设备MAC>&productId=1"
# 期望： {"code":0,"message":"success"}
```

容器日志里能看到设备的请求：

```bash
docker logs aircat-fake | grep '\[cloud\]'
# 2026-10-06 14:20:01 激活请求 /device/active?mac=b0f89324a3ac&productId=1 -> {"code":0,...}
```

### 为什么值得做

不实现假云端时，设备会一直重试激活，**约 14 小时卡死一次**，表现为：

- HA 里数据停更
- 设备不响应 ARP（`ip neigh` 显示 FAILED）
- **只能断电重启**（软件层面无法恢复，因为它的网络栈已经死了）

实现之后重试消失，设备可以长期稳定运行。

---

## 可选：用路由器代替 ARP 欺骗（推荐）

默认方案靠 **ARP 欺骗**把 M1 的流量引到本机 —— 零配置，任何路由器都能用。
但如果你的路由器支持**给单个终端指定网关**，可以换成更干净的方式。

### 原理

M1 的网关指向本机后，它所有出网流量（包括发往 `223.5.5.5` 的 DNS 查询）都会
按**正常路由**经过本机，DNS 拦截依然生效，**不再需要伪造任何 ARP 应答**。

### 怎么做（以 iKuai 为例）

1. **网络设置 → DHCP设置 → DHCP静态分配**，找到 M1 那条（MAC 前缀 `b0:f8:93`）
2. 把它的**网关**改成运行本服务的机器 IP（例如 `192.168.123.6`）
3. 改 `docker-compose.yml`：

   ```yaml
   ARP_SPOOF: "0"
   ```

4. 重启容器：

   ```bash
   docker compose up -d --force-recreate
   ```

### 验证是否生效

停掉欺骗后，等 M1 下一次解析域名（约每小时一次），观察日志：

```bash
docker logs aircat-fake --since 30m | grep 'M1:'
```

- **仍有 M1 的查询** → 网关配置生效 ✅ 可以永久关闭欺骗
- **没有查询了** → M1 没认这个网关设置，把 `ARP_SPOOF` 改回 `"1"`

也可以看 M1 是否还能重连（它会定期重开 TCP 连接）：

```bash
docker logs aircat-fake | grep 'CONNECT from' | tail -5
```

### 注意

- 需要本机开启 IP 转发：`sysctl net.ipv4.ip_forward=1`（多数 NAS/服务器默认已开）
- 本机需要能正常转发（没有防火墙拦截 FORWARD 链）
- **本机若宕机，M1 会失去网络** —— 和 ARP 欺骗方案的风险相同

### 附带好处

如果路由器还能给**单个终端指定 DNS**，可以把 M1 的 DNS 直接指向本机上一个
带 `address=/aircat.phicomm.com/<本机IP>` 的 dnsmasq，那样连 DNS 拦截都不需要了
（本仓库的 `m1_dns_redirect.py` 就可以整个删掉）。
