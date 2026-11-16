#!/usr/bin/env python3
"""Fusionne la configuration AdGuard Home gérée par Vigie dans la configuration en service.

  merge-config.py <géré.yaml> <AdGuardHome.yaml en service | -> <sortie.yaml>

Exécuté par install.sh avec le Python (et PyYAML) de l'image wazuh-manager : rien à installer sur
l'hôte. Sans configuration en service (« - », premier démarrage ou --reset-adguard), la
configuration gérée est reprise telle quelle.

Partage des responsabilités (voir infra/README.md, §6.2) :
- GÉRÉ PAR VIGIE (réécrit à chaque install.sh, depuis .env et les fichiers versionnés) :
  compte « admin », adresse de l'interface, TLS/DoT et certificat, écoute DNS, amonts et
  DNSSEC, liste des clients autorisés (mode ClientID), journal des requêtes lu par Wazuh,
  répertoires de listes locales autorisés, listes de blocage Vigie (identifiants 1, 2, 10, 20,
  30, 90 : profil équilibré/strict) et client « Telephone (Vigie) » du mode ClientID ;
- À L'UTILISATEUR (conservé) : tout le reste, notamment les règles personnalisées de l'interface,
  les listes ajoutées (autres identifiants) et listes d'autorisation, les clients, les services
  bloqués, les réécritures DNS, la limitation de débit, le cache, les statistiques. L'état
  activé/désactivé d'une liste Vigie choisi dans l'interface est conservé tant que son URL ne
  change pas (changement de profil).
"""
import sys

import yaml

MANAGED_FILTER_IDS = {1, 2, 10, 20, 30, 90}
MANAGED_CLIENT = "Telephone (Vigie)"
DNS_KEYS = ("bind_hosts", "port", "serve_plain_dns", "upstream_dns", "bootstrap_dns", "fallback_dns",
            "upstream_mode", "allowed_clients", "enable_dnssec", "edns_client_subnet")
QUERYLOG_KEYS = ("dir_path", "enabled", "file_enabled", "size_memory")


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def merge(managed, cur):
    out = cur
    # Compte admin géré ; autres comptes conservés.
    admin = [u for u in managed.get("users") or [] if u.get("name") == "admin"]
    out["users"] = admin + [u for u in cur.get("users") or [] if u.get("name") != "admin"]
    out.setdefault("http", {})["address"] = managed["http"]["address"]
    out["tls"] = managed["tls"]
    dns = out.setdefault("dns", {})
    for k in DNS_KEYS:
        if k in managed["dns"]:
            dns[k] = managed["dns"][k]
    ql = out.setdefault("querylog", {})
    for k in QUERYLOG_KEYS:
        ql[k] = managed["querylog"][k]
    out.setdefault("filtering", {})["safe_fs_patterns"] = managed["filtering"]["safe_fs_patterns"]

    prev = {f.get("id"): f for f in cur.get("filters") or [] if f.get("id") in MANAGED_FILTER_IDS}
    vigie_filters = []
    for f in managed.get("filters") or []:
        p = prev.get(f["id"])
        if p is not None and p.get("url") == f["url"] and "enabled" in p:
            f = dict(f, enabled=p["enabled"])
        vigie_filters.append(f)
    user_filters = [f for f in cur.get("filters") or [] if f.get("id") not in MANAGED_FILTER_IDS]
    out["filters"] = vigie_filters + user_filters

    clients = out.setdefault("clients", {})
    others = [c for c in clients.get("persistent") or [] if c.get("name") != MANAGED_CLIENT]
    mine = [c for c in (managed.get("clients") or {}).get("persistent") or [] if c.get("name") == MANAGED_CLIENT]
    clients["persistent"] = mine + others
    return out


def main():
    managed = load(sys.argv[1])
    out = managed if sys.argv[2] == "-" else merge(managed, load(sys.argv[2]))
    with open(sys.argv[3], "w", encoding="utf-8") as f:
        f.write("# AdGuard Home — fusion Vigie (infra/adguard/merge-config.py). Voir infra/README.md §6.2.\n")
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)


if __name__ == "__main__":
    main()
