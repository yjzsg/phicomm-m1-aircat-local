#!/bin/bash
# 悟空M1 假云端的网络设置：加别名 IP + DNAT 到容器内的 HTTPS 服务
# 由 systemd 单元 m1-fake-cloud.service 调用
set -u

ALIAS="${ALIAS_IP:-192.168.123.250}"
IFACE="${IFACE_NAME:-enxc84d44294124}"
TARGET="${TARGET_IP:-192.168.123.6}"
PORT="${FAKE_CLOUD_PORT:-9443}"

RULE_ARGS=(-d "$ALIAS" -p tcp --dport 443 -j DNAT --to-destination "$TARGET:$PORT")

case "${1:-}" in
  up)
    ip addr show dev "$IFACE" | grep -q "$ALIAS" \
      || { ip addr add "$ALIAS/24" dev "$IFACE" && echo "已加别名 IP $ALIAS"; }
    iptables -t nat -C PREROUTING "${RULE_ARGS[@]}" 2>/dev/null \
      || { iptables -t nat -A PREROUTING "${RULE_ARGS[@]}" && echo "已加 DNAT $ALIAS:443 -> $TARGET:$PORT"; }
    ;;
  down)
    iptables -t nat -D PREROUTING "${RULE_ARGS[@]}" 2>/dev/null \
      && echo "已删 DNAT" || true
    ip addr del "$ALIAS/24" dev "$IFACE" 2>/dev/null \
      && echo "已删别名 IP" || true
    ;;
  status)
    echo "别名 IP:"; ip -br addr show "$IFACE" | sed 's/^/  /'
    echo "DNAT 规则:"; iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "$ALIAS|$PORT" | sed 's/^/  /' || echo "  无"
    ;;
  *)
    echo "用法: $0 {up|down|status}"; exit 1
    ;;
esac
