#!/usr/bin/env bash
# Host firewall (ufw) matching the ports published by docker-compose.yml.
#   sudo ./firewall/ufw.sh               # SSH + 80 + 443 + 853
#   sudo ./firewall/ufw.sh --wireguard   # + 51820/udp
#   SSH_PORT=2222 sudo ./firewall/ufw.sh
#
# WARNING: Docker inserts its own iptables rules for the published ports, BEFORE the ufw ones:
# ufw can neither close nor restrict a port published by Docker. The real list of exposed
# ports is therefore the one in docker-compose.yml (80, 443, 853; 51820/udp with the wireguard
# profile); this script protects the rest of the host (SSH, system services). To restrict a
# published port (e.g. 853 to some countries/networks), use the DOCKER-USER chain (see
# nftables.conf) or the firewall of the VPS provider.
set -euo pipefail
SSH_PORT="${SSH_PORT:-22}"
command -v ufw >/dev/null || { echo "ufw missing (apt install ufw)"; exit 1; }
ufw default deny incoming
ufw default allow outgoing
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate limited)'
ufw allow 80/tcp comment 'Watchpost: ACME HTTP-01 + HTTPS redirect'
ufw allow 443/tcp comment 'Watchpost: console, mTLS ingestion, SIEM, AdGuard'
ufw allow 853/tcp comment 'Watchpost: DNS-over-TLS (Android private DNS)'
[[ "${1:-}" == --wireguard ]] && ufw allow 51820/udp comment 'Watchpost: WireGuard'
ufw --force enable
ufw status verbose
