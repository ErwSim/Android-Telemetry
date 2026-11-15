#!/usr/bin/env bash
# Pare-feu de l'hôte (ufw) correspondant aux ports publiés par docker-compose.yml.
#   sudo ./firewall/ufw.sh               # SSH + 80 + 443 + 853
#   sudo ./firewall/ufw.sh --wireguard   # + 51820/udp
#   SSH_PORT=2222 sudo ./firewall/ufw.sh
#
# ATTENTION : Docker insère ses propres règles iptables pour les ports publiés, AVANT celles
# d'ufw : ufw ne peut ni fermer ni restreindre un port publié par Docker. La vraie liste des ports
# exposés est donc celle de docker-compose.yml (80, 443, 853 ; 51820/udp avec le profil
# wireguard) ; ce script protège le reste de l'hôte (SSH, services système). Pour restreindre un
# port publié (ex. 853 à certains pays/réseaux), utilisez la chaîne DOCKER-USER (voir
# nftables.conf) ou le pare-feu du fournisseur du VPS.
set -euo pipefail
SSH_PORT="${SSH_PORT:-22}"
command -v ufw >/dev/null || { echo "ufw absent (apt install ufw)"; exit 1; }
ufw default deny incoming
ufw default allow outgoing
ufw limit "$SSH_PORT/tcp" comment 'SSH (limité)'
ufw allow 80/tcp comment 'Vigie : ACME HTTP-01 + redirection HTTPS'
ufw allow 443/tcp comment 'Vigie : console, ingestion mTLS, SIEM, AdGuard'
ufw allow 853/tcp comment 'Vigie : DNS-over-TLS (DNS privé Android)'
[[ "${1:-}" == --wireguard ]] && ufw allow 51820/udp comment 'Vigie : WireGuard'
ufw --force enable
ufw status verbose
