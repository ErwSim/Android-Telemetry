#!/usr/bin/env python3
"""Merges the AdGuard Home configuration managed by Watchpost into the configuration in service.

  merge-config.py <managed.yaml> <AdGuardHome.yaml in service | -> <output.yaml> <levels.json>
                  [--level permissive|balanced|strict] [--default-level LEVEL] [--reset]

Run by install.sh with the Python (and PyYAML) of the wazuh-manager image: nothing to install on
the host. Writes on standard output a line "LEVEL=<key>" (resulting blocking level, empty if the
state of the lists matches no level).

Split of responsibilities (see infra/README.md, §6.2):
- MANAGED BY WATCHPOST (rewritten on every install.sh, from .env and the committed files):
  "admin" and "watchpost-collector" accounts, interface address, TLS/DoT and certificate,
  DNS listener, upstreams and DNSSEC, list of allowed clients (ClientID mode), query log read
  by Wazuh, allowed directories of local lists, PRESENCE, address, name and identifier of the
  lists of the levels file (adguard/levels.json) and of the "Personal rules" list (90),
  "Phone (Watchpost)" client of the ClientID mode;
- STATE DECIDED IN THE CONSOLE (or in the AdGuard interface), KEPT: which lists of the levels
  file are enabled (= the blocking level), and the "! watchpost:begin … ! watchpost:end" block
  of the custom rules (rules set by the Tracking page). Only --level (install.sh option
  --profile) changes the level; --reset (--reset-adguard) keeps them too;
- LEFT TO THE USER (kept): everything else, notably the other custom rules, the added lists
  (other addresses) and allowlists, the clients, the blocked services, the DNS rewrites, the
  rate limiting, the cache, the statistics.

A list is identified by its EXACT address and its kind (blocklist / allowlist), as the collector
does. A list of the file missing from the configuration (first installation, new list in the
repository, list deleted in the interface) takes the state of the current level (the one that the
state of the other lists designates), otherwise of --default-level.
"""
import argparse
import json
import sys

import yaml

# Fixed AdGuard identifiers of the managed lists (the Wazuh rules use them: 30 = threats).
# The "category" field of levels.json is read by the collector; here it is only checked.
LIST_IDS = {"watchpost_base": 1, "watchpost_strict": 2, "hagezi_pro": 10, "hagezi_pro_plus": 11,
            "hagezi_samsung": 20, "hagezi_tif": 30}
PERSONAL = {"id": 90, "url": "/opt/adguardhome/work/userfilters/personal/personal-rules.txt", "name": "Personal rules"}
LEVEL_ORDER = ("permissive", "balanced", "strict")
CATEGORIES = ("threat", "ads", "tracking", "mixed", "custom", "allowlist")
MANAGED_USERS = ("admin", "watchpost-collector")
MANAGED_CLIENT = "Phone (Watchpost)"
BLOCK_BEGIN = "! watchpost:begin"
BLOCK_END = "! watchpost:end"
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
        sys.exit("levels.json: levels permissive, balanced, strict expected")
    missing = set(lv["lists"]) - set(LIST_IDS)
    if missing:
        sys.exit("levels.json: lists without an AdGuard identifier in merge-config.py: " + ", ".join(sorted(missing)))
    # "category" (v1.2): only "threat" changes a behaviour (detect.threat_domain of the collector,
    # which refuses an unknown value at startup); checked here so that installation fails early.
    for key, d in lv["lists"].items():
        c = d.get("category")
        if c is not None and c not in CATEGORIES:
            sys.exit(f"levels.json: unknown category \"{c}\" for {key} ({', '.join(CATEGORIES)})")
        if c == "threat" and d.get("allowlist", False):
            sys.exit(f"levels.json: the allowlist {key} cannot have the threat category")
    if not any(d.get("category") == "threat" for d in lv["lists"].values()):
        print("levels.json: no list of category \"threat\": detect.threat_domain will stay silent",
              file=sys.stderr)
    return lv["lists"], levels


def kind(allowlist):
    return "whitelist_filters" if allowlist else "filters"


def find(cfg, url, allowlist):
    for f in cfg.get(kind(allowlist)) or []:
        if f.get("url") == url:
            return f
    return None


def current_states(lists, cur):
    """State (enabled or not) of the lists of the file that are present in the configuration in service."""
    out = {}
    for key, d in lists.items():
        f = find(cur, d["url"], d.get("allowlist", False))
        if f is not None and "enabled" in f:
            out[key] = bool(f["enabled"])
    return out


def pick_level(states, levels, default):
    """Level consistent with the state of the present lists (the default first, then balanced…)."""
    candidates = [k for k in LEVEL_ORDER if all((key in levels[k]) == on for key, on in states.items())]
    if default in candidates:
        return default
    for k in ("balanced", "strict", "permissive"):
        if k in candidates:
            return k
    return default


def exact_level(enabled, levels):
    for k in LEVEL_ORDER:
        if levels[k] == enabled:
            return k
    return ""


def watchpost_block(cfg):
    rules = cfg.get("user_rules") or []
    begin = [i for i, r in enumerate(rules) if str(r).strip().startswith(BLOCK_BEGIN)]
    end = [i for i, r in enumerate(rules) if str(r).strip() == BLOCK_END]
    if len(begin) == 1 and len(end) == 1 and begin[0] < end[0]:
        return rules[begin[0]:end[0] + 1]
    return []


def build_filters(lists, levels, cur, level, default):
    """Managed lists (levels file + personal rules), then the user's lists."""
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
    p = find(cur, PERSONAL["url"], False)
    managed["filters"].append({"enabled": bool(p.get("enabled", True)) if p else True, "url": PERSONAL["url"],
                               "name": PERSONAL["name"], "id": PERSONAL["id"]})
    managed_ids = set(LIST_IDS.values()) | {PERSONAL["id"]}
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
    ap.add_argument("--default-level", default="balanced", choices=LEVEL_ORDER)
    ap.add_argument("--reset", action="store_true",
                    help="start again from the managed configuration, keeping the level and the watchpost block")
    a = ap.parse_args()

    managed = load_yaml(a.managed)
    cur = {} if a.current == "-" else load_yaml(a.current)
    lists, levels = load_levels(a.levels)
    filters, level = build_filters(lists, levels, cur, a.level, a.default_level)
    if a.current == "-" or a.reset:
        out = managed
        block = watchpost_block(cur)
        out["user_rules"] = (out.get("user_rules") or []) + block
    else:
        out = merge(managed, cur)
    out.update(filters)

    with open(a.output, "w", encoding="utf-8") as f:
        f.write("# AdGuard Home: Watchpost merge (infra/adguard/merge-config.py). See infra/README.md §6.2.\n")
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)
    print("LEVEL=" + level)


if __name__ == "__main__":
    main()
