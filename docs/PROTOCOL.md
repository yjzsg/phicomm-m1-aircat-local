# 悟空M1 通信协议（原厂固件）

本文是从**实际报文**反推出来的，主要依据：

1. [corbamico/phicomm-aircat-srv](https://github.com/corbamico/phicomm-aircat-srv) 里的 Go 源码和
   `docs/misc/phicomm-m1.pcap`（一份真实抓包）
2. 本机设备的实测报文

所有结论都标了出处。**没有可靠依据的地方会明确写「未知」**，不要当成事实。

---

## 1. 传输层

- 明文 TCP，端口 **9000**
- 设备启动后解析 `aircat.phicomm.com`，然后直连该域名
- **没有 TLS**，所以本地伪装服务器不需要证书

## 2. 帧结构

```
┌─────────────────┬──────────────┬───────────────┐
│  28 字节报文头   │  JSON 正文    │  \xff#END#    │
└─────────────────┴──────────────┴───────────────┘
```

尾部结束符是 6 字节：`FF 23 45 4E 44 23`，即 ASCII 的 `\xff#END#`。

### 2.1 报文头（28 字节）

来自 Go 源码的 `Rawheader` 结构（`internal/aircat/message.go`）：

```go
//sizeof rawheader = 16 + 12 = 28
type Rawheader struct {
	Unknown [16]uint8 //fixed for every device
	Mac     [8]uint8  //00-mac-00
	Length  uint8     //length of (padding + msgType + json)
	Padding [2]uint8  //fixed as 00 00
	MsgType uint8     //1:active,2:control,4:report
}
```

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 16 | `Unknown` | 源码注释「fixed for every device」。**实测本机设备是全 0**（首字节 `aa`） |
| 16 | 8 | `Mac` | `00` + MAC(6 字节) + `00` |
| 24 | 1 | `Length` | **含义随方向变化，见 §3** |
| 25 | 2 | `Padding` | 固定 `00 00` |
| 27 | 1 | `MsgType` | `1`=active `2`=control `4`=report |

**注意**：网上有些文章把 `Length/Padding/MsgType` 这 5 字节单独叫作「前缀」，
和前面 23 字节分开描述。这只是记法差异，字节布局是一致的。

### 2.2 设备实际报文对照

本机设备上报的一帧（十六进制）：

```
aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   <- Unknown（全 0，首字节 aa）
b0 f8 93 24 a3 ac 00                                 <- Mac 字段：00 + MAC + 00
4e 00 00 04                                          <- Length=0x4e  Padding=0000  MsgType=4
{ "humidity": ... }                                  <- JSON（75 字节）
ff 23 45 4e 44 23                                    <- \xff#END#
```

`Length = 0x4e = 78 = 3 + 75` ✓（见 §3）

> 真实抓包里的设备 `Unknown` 字段不是全 0，例如
> `aa 5f 01 8f 5f d1 39 8f 0b 00 00 00 00 00 00 00`。
> 那 6 个字节看起来是 MAC 的**字节倒序 + 半字节交换**，但本机设备发的是全 0，
> 所以**没有验证这个算法**，也就不依赖它 —— 服务器直接沿用收到的头即可。

---

## 3. ⚠️ Length 字段：两个方向含义不同

**这是整个协议里最容易踩的坑，也是亮度控制能不能生效的关键。**

| 方向 | Length 的值 |
|---|---|
| 设备 → 服务器 | `3 + len(JSON)` |
| **服务器 → 设备** | **整帧总长度 = `28 + len(JSON) + 6`** |

### 证据

用 `phicomm-m1.pcap` 里服务器发出的 5 个报文反推，全部吻合：

| 报文 | JSON 长度 | 抓包里的 Length | 校验 |
|---|---|---|---|
| `{"brightness":"25","type":2}` | 28 | `0x3e` = 62 | 28+28+6 = 62 ✓ |
| `{"brightness":"0","type":2}` | 27 | `0x3d` = 61 | 28+27+6 = 61 ✓ |
| `{"brightness":"100","type":2}` | 29 | `0x3f` = 63 | 28+29+6 = 63 ✓ |
| `{"type":5,"status":1}` | 21 | `0x37` = 55 | 28+21+6 = 55 ✓ |
| `{"sleep":"1","startTime":82800,...}` | 56 | `0x5a` = 90 | 28+56+6 = 90 ✓ |

同时设备发出的报文用的是另一套：

| 设备报文 | JSON 长度 | Length | 校验 |
|---|---|---|---|
| 传感器上报 | 75 | `0x4e` = 78 | 3+75 = 78 ✓ |
| 状态帧 `\x00\x03\x00\x00\x01` | 0 | `0x03` = 3 | 3+0 = 3 ✓ |

### 后果

按 `3 + len(JSON)` 给服务器方向的报文算长度：

- **长度偏小** → 设备按错误长度截断解析 → **指令被忽略**（亮度点了没反应）
- 更糟的是 **解析器会失步** → 设备彻底停止上报，TCP 连接还在但一条数据都不发，
  **只能断电重启恢复**

### 网上流传的错误示例

一些文章给的亮度指令是：

```
\x00\x18\x00\x00\x02{"brightness":"50.0","type":2}\xff#END#
```

`0x18` = 24，但它对应的 JSON 有 30 字节，正确值应该是
`28 + 30 + 6 = 64 = 0x40`。**这个 `0x18` 是错的**，照抄会导致上面的失步问题。

---

## 4. 消息类型

`MsgType` 三个取值（来自 Go 源码注释）：

| 值 | 含义 |
|---|---|
| 1 | active（设备主动） |
| 2 | control（服务器下发） |
| 4 | report（设备上报） |

---

## 5. 设备 → 服务器

### 5.1 传感器上报（MsgType=4）

```json
{ "humidity": "73.04", "temperature": "17.27", "value": "46", "hcho": "20" }
```

| 字段 | 说明 |
|---|---|
| `humidity` | 湿度 %，字符串 |
| `temperature` | 温度 °C，字符串 |
| `value` | **PM2.5（µg/m³）** |
| `hcho` | 甲醛，需 **除以 1000** 才是 mg/m³ |

`value` 是 PM2.5 这点是实测确认的：用灰尘测试时该值从 2 涨到 11。

上报间隔约 **3 秒**。

### 5.2 状态帧

```
\x00\x03\x00\x00\x01\xff#END#
```

即 Length=3、Padding=0000、MsgType=1、**JSON 为空**。

设备在**刚建立 TCP 连接后**会先发这一帧。含义未确认 ——
从字节看像是「设备已就绪/active」的握手。

---

## 6. 服务器 → 设备

### 6.1 心跳 / 请求上报（MsgType=2）

```json
{"type":5,"status":1}
```

整帧 55 字节，Length = `0x37`。

协议文档说设备在收到亮度指令后会暂停上报，需要靠心跳唤醒。
**本机实测设备收到后没有回 ACK**，但发这条不会让设备失步，可以安全定期发送。

### 6.2 亮度设置（MsgType=2）

```json
{"brightness":"25","type":2}
```

- 取值 **`0` / `25` / `50` / `100`**（`0` = 关屏）
- **不带 `mac` 字段**（和抓包一致）
- 设备**不回 ACK**，只能靠肉眼确认屏幕变化
- 收到后不会中断上报（长度正确的前提下）

### 6.3 定时休眠配置（MsgType=2）

```json
{"sleep":"1","startTime":82800,"endTime":21600,"type":1}
```

抓包里出现过，整帧 90 字节。`82800` = 23:00，`21600` = 06:00（秒）。
**本项目没有实现这个功能**，仅记录。

---

## 7. 用最小代码验证协议

```python
import json

MAC = bytes.fromhex("aabbccddeeff")
END = b"\xff#END#"


def header(msg_type: int, length: int) -> bytes:
    # 28 字节头：16 unknown + 8 mac字段(00+mac+00) + 1 length + 2 padding + 1 type
    return (b"\xaa" + b"\x00" * 16 + MAC + b"\x00"
            + bytes([length]) + b"\x00\x00" + bytes([msg_type]))


def frame(json_str: str, msg_type: int = 2) -> bytes:
    j = json_str.encode()
    length = 28 + len(j) + 6          # 服务器方向的规则
    return header(msg_type, length) + j + END


# 心跳：整帧 55 字节，Length=0x37
assert len(frame('{"type":5,"status":1}')) == 55
assert frame('{"type":5,"status":1}')[24] == 0x37

# 亮度 25：整帧 62 字节，Length=0x3e
assert len(frame('{"brightness":"25","type":2}')) == 62
assert frame('{"brightness":"25","type":2}')[24] == 0x3e
```

> `header()` 里 unknown 段写的是全 0。抓包里的设备在这段有非 0 数据，
> 但本机设备是全 0，且实测能正常工作，所以直接沿用设备发来的头最稳妥。

---

## 8. 未解明的地方

诚实起见列出来，避免后人重复踩坑：

1. **`Unknown` 字段的语义** —— 源码只说「每个设备固定」。抓包里那 6 字节疑似
   MAC 的变形，但本机设备全 0，无法验证。
2. **状态帧 `\x00\x03\x00\x00\x01` 的作用** —— 只在连接建立时出现，含义未确认。
3. **亮度指令为什么没有 ACK** —— 协议文档说有，实测没有。
4. **设备失步的精确触发条件** —— 观察到「长度错误」会导致失步，但边界
   （比如长度偏大 vs 偏小）没有系统测试。
