#!/usr/bin/env python3
"""Fusionne la configuration AdGuard Home gérée par Vigie dans la configuration en service.

  merge-config.py <géré.yaml> <AdGuardHome.yaml en service | -> <sortie.yaml> <niveaux.json>
                  [--level permissif|equilibre|strict] [--default-level NIVEAU] [--reset]

Exécuté par install.sh avec le Python (et PyYAML) de l'image wazuh-manager : rien à installer sur
l'hôte. Écrit sur la sortie standard une ligne « NIVEAU=<clé> » (niveau de blocage résultant, vide
si l'état des listes ne correspond à aucun niveau).

Partage des responsabilités (voir infra/README.md, §6.2) :
- GÉRÉ PAR VIGIE (réécrit à chaque install.sh, depuis .env et les fichiers versionnés) :
  comptes « admin » et « vigie-collecteur », adresse de l'interface, TLS/DoT et certificat,
  écoute DNS, amonts et DNSSEC, liste des clients autorisés (mode ClientID), journal des
  requêtes lu par Wazuh, répertoires de listes locales autorisés, PRÉSENCE, adresse, nom et
  identifiant des listes du fichier de niveaux (adguard/niveaux.json) et de la liste
  « Règles personnelles » (90), client « Telephone (Vigie) » du mode ClientID ;
- ÉTAT DÉCIDÉ DANS LA CONSOLE (ou l'interface d'AdGuard), CONSERVÉ : quelles listes du fichier
  de niveaux sont activées (= le niveau de blocage), et le bloc « ! vigie:begin … ! vigie:end »
  des règles personnalisées (règles posées par la vue « pistage »). Seuls --level (option
  --profile d'install.sh) change le niveau ; --reset (--reset-adguard) les garde aussi ;
- À L'UTILISATEUR (conservé) : tout le reste, notamment les autres règles personnalisées, les
  listes ajoutées (autres adresses) et listes d'autorisation, les clients, les services
  bloqués, les réécritures DNS, la limitation de débit, le cache, les statistiques.

Une liste est reconnue par son adresse EXACTE et son genre (blocage / autorisation), comme le fait
le collecteur. Une liste du fichier absente de la configuration (première installation, nouvelle
liste du dépôt, liste supprimée dans l'interface) prend l'état du niveau courant (celui que l'état
des autres listes désigne), sinon de --default-level.
"""
import argparse
import json
import sys

import yaml

# Identifiants AdGuard fixes des listes gérées (les règles Wazuh s'en servent : 30 = menaces).
LIST_IDS = {"vigie_base": 1, "vigie_strict": 2, "hagezi_pro": 10, "hagezi_pro_plus": 11,
            "hagezi_samsung": 20, "hagezi_tif": 30}
PERSO = {"id": 90, "url": "/opt/adguardhome/work/userfilters/perso/regles-perso.txt", "name": "Règles personnelles"}
LEVEL_ORDER = ("permissif", "equilibre", "strict")
MANAGED_USERS = ("admin", "vigie-collecteur")
MANAGED_CLIENT = "Telephone (Vigie)"
BLOCK_BEGIN = "! vigie:begin"
BLOCK_END = "! vigie:end"
DNS_KEYS = ("bind_hosts", "port", "serve_plain_dns", "upstream_dns", "bootstrap_dns", "fallback_dns",
            "upstream_mode", "allowed_clients", "enable_dnssec", "edns_client_subnet")
QUERYLOG_KEYS = ("dir_path", "enabled", "file_enabled", "size_memory")


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_levels(path):
    with open(path, encoding="utf-8") as f:
        lv = json.load(f)
    levels = {l["key"]: set(l["lists"]) for l in lv["levels"]}
    if set(levels) != set(LEVEL_ORDER):
        sys.exit("niveaux.json : niveaux permissif, equilibre, strict attendus")
    missing = set(lv["lists"]) - set(LIST_IDS)
    if missing:
        sys.exit("niveaux.json : listes sans identifiant AdGuard dans merge-config.py : " + ", ".join(sorted(missing)))
    return lv["lists"], levels


def kind(allowlist):
    return "whitelist_filters" if allowlist else "filters"


def find(cfg, url, allowlist):
    for f in cfg.get(kind(allowlist)) or []:
        if f.get("url") == url:
            return f
    return None


def current_states(lists, cur):
    """État (activée ou non) des listes du fichier présentes dans la configuration en service."""
    out = {}
    for key, d in lists.items():
        f = find(cur, d["url"], d.get("allowlist", False))
        if f is not None and "enabled" in f:
            out[key] = bool(f["enabled"])
    return out


def pick_level(states, levels, default):
    """Niveau cohérent avec l'état des listes présentes (le défaut d'abord, puis équilibré…)."""
    candidates = [k for k in LEVEL_ORDER if all((key in levels[k]) == on for key, on in states.items())]
    if default in candidates:
        return default
    for k in ("equilibre", "strict", "permissif"):
        if k in candidates:
            return k
    return default


def exact_level(enabled, levels):
    for k in LEVEL_ORDER:
        if levels[k] == enabled:
            return k
    return ""


def vigie_block(cfg):
    rules = cfg.get("user_rules") or []
    begin = [i for i, r in enumerate(rules) if str(r).strip().startswith(BLOCK_BEGIN)]
    end = [i for i, r in enumerate(rules) if str(r).strip() == BLOCK_END]
    if len(begin) == 1 and len(end) == 1 and begin[0] < end[0]:
        return rules[begin[0]:end[0] + 1]
    return []


def build_filters(lists, levels, cur, level, default):
    """Listes gérées (fichier de niveaux + règles personnelles) puis listes de l'utilisateur."""
    states = current_states(lists, cur)
    if level:
        states = {key: key in levels[level] for key in lists}
    else:
        fallback = pick_level(states, levels, default)
        states = {key: states.get(key, key in levels[fallback]) for key in lists}
    managed = {"filters": [], "whitelist_filters": []}
    for key in sorted(lists, key=lambda k: LIST_IDS[k]):
        d = lists[key]
        managed[kind(d.get("allowlist", False))].append(
            {"enabled": states[key], "url": d["url"], "name": d["name"], "id": LIST_IDS[key]})
    p = find(cur, PERSO["url"], False)
    managed["filters"].append({"enabled": bool(p.get("enabled", True)) if p else True, "url": PERSO["url"],
                               "name": PERSO["name"], "id": PERSO["id"]})
    managed_ids = set(LIST_IDS.values()) | {PERSO["id"]}
    out = {}
    for k in ("filters", "whitelist_filters"):
        urls = {f["url"] for f in managed[k]}
        user = [f for f in cur.get(k) or [] if f.get("url") not in urls and f.get("id") not in managed_ids]
        out[k] = managed[k] + user
    enabled = {key for key, on in states.items() if on}
    return out, exact_level(enabled, levels)


def merge(managed, cur):
    out = cur
    names = set(MANAGED_USERS)
    mine = [u for u in managed.get("users") or [] if u.get("name") in names]
    out["users"] = mine + [u for u in cur.get("users") or [] if u.get("name") not in names]
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
    clients = out.setdefault("clients", {})
    others = [c for c in clients.get("persistent") or [] if c.get("name") != MANAGED_CLIENT]
    mine = [c for c in (managed.get("clients") or {}).get("persistent") or [] if c.get("name") == MANAGED_CLIENT]
    clients["persistent"] = mine + others
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("managed")
    ap.add_argument("current")
    ap.add_argument("output")
    ap.add_argument("levels")
    ap.add_argument("--level", default="", choices=("",) + LEVEL_ORDER)
    ap.add_argument("--default-level", default="equilibre", choices=LEVEL_ORDER)
    ap.add_argument("--reset", action="store_true",
                    help="repartir de la configuration gérée en gardant le niveau et le bloc vigie")
    a = ap.parse_args()

    managed = load_yaml(a.managed)
    cur = {} if a.current == "-" else load_yaml(a.current)
    lists, levels = load_levels(a.levels)
    filters, level = build_filters(lists, levels, cur, a.level, a.default_level)
    if a.current == "-" or a.reset:
        out = managed
        block = vigie_block(cur)
        out["user_rules"] = (out.get("user_rules") or []) + block
    else:
        out = merge(managed, cur)
    out.update(filters)

    with open(a.output, "w", encoding="utf-8") as f:
        f.write("# AdGuard Home — fusion Vigie (infra/adguard/merge-config.py). Voir infra/README.md §6.2.\n")
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)
    print("NIVEAU=" + level)


if __name__ == "__main__":
    main()
