#!/bin/bash
# 悟空M1 假云端的网络设置：只劫持设备流量到本机的 HTTPS 服务
#
# 设计说明（2026-10-07 改）：
#   原先用「别名 IP 192.168.123.250 + 无条件 DNAT」，但别名 IP 会被 fnOS 的
#   网络管理清掉，导致 DNAT 指向一个不存在的地址、设备连不上。
#   改为「本机真实 IP + 按源地址匹配的 DNAT」：不依赖别名 IP，且只影响这台设备。
set -u

IFACE="${IFACE_NAME:-enxc84d44294124}"
M1_IP="${M1_IP:-192.168.123.54}"
LOCAL_IP="${LOCAL_IP:-192.168.123.6}"
PORT="${FAKE_CLOUD_PORT:-9443}"

RULE_ARGS=(-s "$M1_IP" -d "$LOCAL_IP" -p tcp --dport 443
           -j DNAT --to-destination "$LOCAL_IP:$PORT")

case "${1:-}" in
  up)
    iptables -t nat -C PREROUTING "${RULE_ARGS[@]}" 2>/dev/null \
      || { iptables -t nat -A PREROUTING "${RULE_ARGS[@]}" \
           && echo "已加 DNAT: $M1_IP -> $LOCAL_IP:443 转发到 :$PORT"; }
    # 清理旧版残留（别名 IP 和无条件 DNAT）
    iptables -t nat -D PREROUTING -d 192.168.123.250 -p tcp --dport 443 \
      -j DNAT --to-destination "$LOCAL_IP:$PORT" 2>/dev/null \
      && echo "已清理旧的无条件 DNAT" || true
    ip addr show dev "$IFACE" | grep -q "192.168.123.250" \
      && { ip addr del 192.168.123.250/24 dev "$IFACE" 2>/dev/null \
           && echo "已清理旧的别名 IP"; } || true
    ;;
  down)
    iptables -t nat -D PREROUTING "${RULE_ARGS[@]}" 2>/dev/null \
      && echo "已删 DNAT" || true
    ;;
  status)
    echo "DNAT 规则:"
    iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
      | grep -E "num|DNAT" | sed 's/^/  /'
    echo "接口地址:"
    ip -br addr show "$IFACE" | sed 's/^/  /'
    ;;
  *)
    echo "用法: $0 {up|down|status}"; exit 1
    ;;
esac
