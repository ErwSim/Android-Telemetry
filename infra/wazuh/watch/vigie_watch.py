#!/usr/bin/env python3
"""Sonde Vigie exécutée par le manager Wazuh (wodle « command », toutes les 10 min).

Une règle Wazuh ne peut pas se déclencher sur une ABSENCE d'événement ni comparer des numéros de
séquence. Cette sonde lit la fin de l'export NDJSON du collecteur et écrit sur sa sortie standard
une ligne JSON par constat ; le manager les analyse comme des journaux (règles 1003xx) :

  {"vigie_watch":{"check":"silence", ...}}   aucun événement reçu depuis N minutes
  {"vigie_watch":{"check":"resumed", ...}}   l'appareil émet à nouveau
  {"vigie_watch":{"check":"seq_gap", ...}}   numéros de séquence manquants (événements perdus/supprimés)
  {"vigie_watch":{"check":"seq_reset", ...}} compteur revenu en arrière (réinstallation, effacement)

Un même constat n'est émis qu'une fois par épisode (état persistant dans /var/ossec/logs).
Python standard uniquement (interpréteur embarqué de Wazuh). Variables d'environnement :
VIGIE_WATCH_SILENCE_MIN (60), VIGIE_WATCH_GRACE_MIN (30), VIGIE_WATCH_EXPORT (/var/vigie/events.ndjson).
"""
import glob
import json
import os
import sys
import time
from datetime import datetime, timezone

EXPORT = os.environ.get("VIGIE_WATCH_EXPORT", "/var/vigie/events.ndjson")
STATE = os.environ.get("VIGIE_WATCH_STATE", "/var/ossec/logs/vigie-watch-state.json")
SILENCE_MIN = int(os.environ.get("VIGIE_WATCH_SILENCE_MIN", "60"))
GRACE_MIN = int(os.environ.get("VIGIE_WATCH_GRACE_MIN", "30"))
TAIL_BYTES = int(os.environ.get("VIGIE_WATCH_TAIL_BYTES", str(32 * 1024 * 1024)))
MAX_GAP_REPORT = 50


def parse_ts(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return None


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tail_lines(path, nbytes):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - nbytes)
            f.seek(start)
            data = f.read()
    except OSError:
        return []
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # première ligne probablement incomplète
    return lines


def load_events():
    """Événements récents, du plus ancien au plus récent (fichier tourné .1 puis courant)."""
    files = sorted(glob.glob(EXPORT + ".[0-9]*"), key=lambda p: -int(p.rsplit(".", 1)[1]))[-1:]
    files.append(EXPORT)
    budget = TAIL_BYTES
    out = []
    for path in reversed(files):  # le courant d'abord pour le budget
        if budget <= 0:
            break
        lines = tail_lines(path, budget)
        budget -= sum(len(x) + 1 for x in lines)
        out = lines + out
    for raw in out:
        if not raw.startswith(b'{"'):
            continue
        try:
            v = json.loads(raw).get("vigie")
        except ValueError:
            continue
        if isinstance(v, dict) and v.get("device_id"):
            yield v


def emit(obj):
    sys.stdout.write(json.dumps({"vigie_watch": obj}, separators=(",", ":"), ensure_ascii=False) + "\n")


def main():
    now = time.time()
    try:
        with open(STATE) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    devices = state.setdefault("devices", {})

    recent = {}
    for v in load_events():
        dev = v["device_id"]
        r = recent.setdefault(dev, {"seqs": {}, "last": 0, "name": v.get("device_name", ""), "overflow": False})
        rt = parse_ts(v.get("received_at", "")) or 0
        r["last"] = max(r["last"], rt)
        if v.get("type") == "agent.buffer_overflow":
            r["overflow"] = True
        seq = v.get("seq")
        if isinstance(seq, int) and "#" not in str(v.get("id", "")):
            prev = r["seqs"].get(seq)
            r["seqs"][seq] = rt if prev is None else min(prev, rt)

    for dev, r in recent.items():
        d = devices.setdefault(dev, {"last_seen": 0, "silent": False, "max_seq": None})
        d["name"] = r["name"] or d.get("name", "")
        d["last_seen"] = max(d["last_seen"], r["last"])
        if not r["seqs"]:
            continue
        cutoff = now - GRACE_MIN * 60
        confirmed = sorted(s for s, t in r["seqs"].items() if t <= cutoff)
        newest = max(r["seqs"])
        if d["max_seq"] is None:
            d["max_seq"] = confirmed[-1] if confirmed else None
            continue
        if newest < d["max_seq"] - 1000 and min(r["seqs"]) < d["max_seq"] - 1000:
            emit({"check": "seq_reset", "device_id": dev, "device_name": d["name"],
                  "previous_max_seq": d["max_seq"], "current_max_seq": newest})
            d["max_seq"] = confirmed[-1] if confirmed else newest
            continue
        if not confirmed or confirmed[-1] <= d["max_seq"]:
            continue
        seen = set(r["seqs"])
        lo, hi = d["max_seq"] + 1, confirmed[-1]
        if lo >= min(r["seqs"]):  # fenêtre lue suffisante pour juger
            missing = [s for s in range(lo, hi + 1) if s not in seen]
            if missing:
                emit({"check": "seq_gap", "device_id": dev, "device_name": d["name"],
                      "missing_count": len(missing), "first_missing": missing[0],
                      "last_missing": missing[-1], "sample": missing[:MAX_GAP_REPORT],
                      "explained": "buffer_overflow" if r["overflow"] else "none"})
        d["max_seq"] = hi

    for dev, d in devices.items():
        if not d["last_seen"]:
            continue
        silent_min = int((now - d["last_seen"]) / 60)
        if silent_min >= SILENCE_MIN and not d["silent"]:
            d["silent"] = True
            emit({"check": "silence", "device_id": dev, "device_name": d.get("name", ""),
                  "last_seen": iso(d["last_seen"]), "silence_min": silent_min, "threshold_min": SILENCE_MIN})
        elif silent_min < SILENCE_MIN and d["silent"]:
            d["silent"] = False
            emit({"check": "resumed", "device_id": dev, "device_name": d.get("name", ""),
                  "last_seen": iso(d["last_seen"])})

    # Purge quotidienne des archives brutes compressées du manager (les données restent dans
    # l'indexeur, soumises à la politique de rétention ISM).
    if now - state.get("last_purge", 0) > 86400:
        days = int(os.environ.get("VIGIE_ARCHIVES_FILE_DAYS", "14"))
        for p in glob.glob("/var/ossec/logs/archives/*/*/*.gz") + glob.glob("/var/ossec/logs/alerts/*/*/*.gz"):
            try:
                if now - os.path.getmtime(p) > days * 86400:
                    os.remove(p)
            except OSError:
                pass
        state["last_purge"] = now

    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


if __name__ == "__main__":
    main()
