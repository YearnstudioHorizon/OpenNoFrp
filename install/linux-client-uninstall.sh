#!/bin/bash
# OpenNoFrp 客户端卸载脚本 (Linux)。
#
# 仅按白名单删除，依据 docs/02-risk-assessment.md 第 5 节：
#   - 停止并禁用 opennofrp-client systemd 单元（该单元自身会通过 ExecStopPost
#     运行 "opennofrp-client tproxy-teardown"，移除此 Client 实例曾创建的
#     每一条 TPROXY iptables 规则 / ip rule / ip route / sysctl 修改 -- 依据
#     其自身持久化的状态文件，而非猜测）
#   - 作为纵深防御的双保险措施，再次直接显式运行
#     tproxy-teardown，以防服务早已停止、
#     ExecStopPost 从未触发
#   - 仅删除以下内容：/etc/systemd/system/opennofrp-client.service、
#     /opt/opennofrp-client/、/var/lib/opennofrp-client/
#   - 默认不删除 /etc/opennofrp-client/client.toml（你的配置及其中的任何密钥
#     都会保留，除非传入 --purge-config）
#   - 绝不运行笼统的 "iptables -F" / "nft flush ruleset" / "ip route
#     flush" -- 只处理 opennofrp 自身所跟踪的那些规则

set -euo pipefail

PURGE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --purge-config) PURGE_CONFIG=1 ;;
    *) ;;
  esac
done

INSTALL_DIR="/opt/opennofrp-client"
CONFIG_DIR="/etc/opennofrp-client"
STATE_DIR="/var/lib/opennofrp-client"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-client.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-client"

log() { echo "[opennofrp-uninstall] $*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "[opennofrp-uninstall] ERROR: must be run as root" >&2
  exit 1
fi

if systemctl show -p ExecStart --value opennofrp-client.service 2>/dev/null | grep -Fq '/opt/opennofrp/opennofrp-client'; then
  log "Legacy client installation detected. Follow the upgrade notes to remove it safely."
  exit 1
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^opennofrp-client\.service'; then
  log "stopping and disabling opennofrp-client.service"
  systemctl stop opennofrp-client.service 2>/dev/null || true
  systemctl disable opennofrp-client.service 2>/dev/null || true
else
  log "opennofrp-client.service not registered, skipping"
fi

if [ -x "$BINARY_DEST" ]; then
  log "running tproxy-teardown directly (belt-and-suspenders, in case the service's ExecStopPost didn't run)"
  "$BINARY_DEST" tproxy-teardown -state-dir "$STATE_DIR" || { log "teardown failed; keeping the recovery journal and binary"; exit 1; }
else
  log "binary not found at $BINARY_DEST, cannot run tproxy-teardown -- if TPROXY rules are still active, remove them manually (see docs/01-architecture.md section 6.1 for what to look for: iptables-legacy mangle rules commented 'opennofrp-port-*', ip rule for fwmark 0x1, ip route table 100)"
fi

if [ -f "$SYSTEMD_UNIT" ]; then
  log "removing $SYSTEMD_UNIT"
  rm -f "$SYSTEMD_UNIT"
  systemctl daemon-reload
fi

if [ -d "$INSTALL_DIR" ]; then
  log "removing $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
fi

if [ "$PURGE_CONFIG" -eq 1 ]; then
  log "--purge-config given: removing client config and state"
  rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
else
  log "keeping $CONFIG_DIR and $STATE_DIR"
fi

log "uninstall complete. Verifying no leftover TPROXY rules:"
if command -v iptables-legacy >/dev/null 2>&1; then
  LEFTOVER=$(iptables-legacy -t mangle -L -n -v 2>/dev/null | grep -c 'opennofrp-' || true)
  if [ "${LEFTOVER:-0}" -gt 0 ]; then
    echo "[opennofrp-uninstall] WARNING: $LEFTOVER opennofrp-tagged mangle rule(s) still present:" >&2
    iptables-legacy -t mangle -L -n -v | grep 'opennofrp-' >&2
    echo "[opennofrp-uninstall] remove manually with: iptables-legacy -t mangle -D <CHAIN> <matching rule spec>" >&2
  else
    log "clean: no opennofrp-tagged mangle rules remain"
  fi
fi
