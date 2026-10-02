# phicomm-m1-aircat-local

让**斐讯悟空M1 空气检测仪**（原厂固件）脱离已经死掉的官方云，在本地跑起来，并把数据接进 Home Assistant。

> Run a Phicomm Wukong M1 air detector (stock firmware) fully offline by impersonating
> the dead `aircat.phicomm.com` server. Includes a targeted DNS/ARP hijack, the fake
> server and an HA MQTT integration. See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the
> reverse-engineered protocol — especially the **direction-dependent `Length` field**,
> which is what makes brightness control actually work.

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

```
        ┌──────────────┐
        │  悟空M1      │  开机 -> 解析 aircat.phicomm.com -> 连 :9000
        │ 192.168.1.54 │
        └──────┬───────┘
               │ ① DNS 查询被拦截（ARP 欺骗把网关指向本机）
               ▼
     ┌───────────────────┐
     │ m1-dns-redirect   │  只拦截 aircat.phicomm.com，其余转发真上游
     └─────────┬─────────┘
               │ ② 解析结果 = 本机
               ▼
     ┌───────────────────┐
     │ aircat-fake       │  伪装 :9000，收报文 -> 解析 -> 发 MQTT
     └─────────┬─────────┘
               │ ③ MQTT
               ▼
     ┌───────────────────┐
     │ Home Assistant    │  传感器 + 屏幕亮度灯 + 数据停更告警
     └───────────────────┘
```

只有两个容器，就够跑起来了。

## 目录

```
docker-compose.yml                          两个 service，一条命令起全套
scripts/aircat_server.py                    假 aircat 服务器（纯标准库，自带极简 MQTT 客户端）
scripts/m1_dns_redirect.py                  定向 ARP + DNS 劫持，只针对一台设备
data/                                       运行时产物（aircat.log），已在 .gitignore 里
homeassistant/configuration-snippet.yaml    HA 的传感器 + 屏幕亮度灯 + 停更告警
docs/PROTOCOL.md                            逆向出来的协议细节
```

## 部署

### 0. 前置

- 一台 24 小时开机的 Linux 机器（NAS / 树莓派 / 软路由都行）
- Docker + Docker Compose
- 一个 MQTT broker（这里假设和 Home Assistant 用同一个）
- 悟空M1 和这台机器在**同一个二层网络**里（ARP 劫持需要）

### 1. 找到设备的 MAC 和 IP

路由器 DHCP 客户端列表里找 OUI 为 **`b0:f8:93`**（MXCHIP/庆科 WiFi 模块）的设备。
也可以先只起 aircat 服务，它会把收到的报文头打到日志里。

### 2. 改配置

```bash
git clone https://github.com/yjzsg/phicomm-m1-aircat-local.git
cd phicomm-m1-aircat-local
ip -br link                    # 看连局域网的网卡名，填到 IFACE
vim docker-compose.yml         # 把 CHANGE_ME 和 aabbccddeeff 全换掉
```

要改的一共 6 处：

| 位置 | 改成 |
|---|---|
| `MQTT_PASS` | 你的 MQTT 密码 |
| `aabbccddeeff`（四处：三个 topic + `M1_MAC`） | 你设备的 MAC |
| `IFACE` | 服务器上连局域网的网卡名 |
| `M1_IP` / `GW_IP` / `FAKE_IP` | 设备 IP / 网关 IP / 本机 IP |

### 3. 启动

```bash
docker compose up -d
docker compose logs -f aircat
```

看到 `aircat fake server starting on 0.0.0.0:9000` 就对了。

### 4. 给 M1 断电重启

它开机后会解析到我们的服务器并开始上报，`docker compose logs -f aircat` 里
应该每 3 秒左右出现一条 `json={...}`。

### 5. 接入 Home Assistant

把 `homeassistant/configuration-snippet.yaml` 里的内容并入 HA 的 `configuration.yaml`，
把 `aabbccddeeff` 全部换成你的 MAC，重启 HA。

得到 5 个实体（温度 / 湿度 / PM2.5 / 甲醛 / 屏幕亮度），外加一条数据停更告警自动化。

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

**现象**：`ss -tn | grep 9000` 显示 TCP 连接还在，但日志里不再有 `json=` 帧，
上报频率从 3 秒退化到几分钟或完全停止。

**原因**：给设备发过**长度字段错误**的报文，固件解析器失步了。
这是全局状态，重连 TCP 不会复位。

**处理**：**给 M1 断电重启**。然后检查是不是有代码在发长度不对的报文。

配置里的「数据停更告警」自动化就是为这个场景准备的 —— 超过 10 分钟没数据会发
HA 通知。它用的是 HA 实体自带的 `last_updated`，不需要额外容器。

### WiFi 图标一直闪

说明设备还没连上服务器。检查：
1. `m1-dns-redirect` 是否在跑（这个容器停了设备就解析不到域名）
2. `IFACE` 填对了没有
3. 设备和服务器是否真在同一网段

## 已知限制

- **只支持单台设备**：ARP/DNS 劫持只针对一个 IP
- **ARP 劫持需要二层可达**：跨网段、AP 隔离的环境用不了
- **屏幕亮度无法读取**：设备从不上报当前亮度，HA 里的状态是「我们发过什么就记什么」
- **甲醛单位**：设备原始值是 `hcho/1000`，这里按 mg/m³ 上报

## 参考

- [corbamico/phicomm-aircat-srv](https://github.com/corbamico/phicomm-aircat-srv) —— Go/Rust/C# 的服务器实现，仓库里有真实抓包 `phicomm-m1.pcap`，本项目的协议结论大量参考它
- [a2633063/zM1](https://github.com/a2633063/zM1) —— 第三方固件（协议不同，走 MQTT）

## License

MIT
