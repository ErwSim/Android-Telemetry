#!/usr/bin/env python3
"""Notification Vigie : intégration Wazuh appelée par wazuh-integratord pour chaque alerte retenue
(niveau >= VIGIE_NOTIFY_LEVEL, plus le silence de l'agent). Arguments : <fichier d'alerte JSON> …

Envoie, selon /var/ossec/etc/vigie-notify.json (écrit par vigie-init.sh depuis .env) :
- un POST JSON simple vers un webhook : {"title", "message", "priority", "tags"} (+ "topic" si
  défini : format de publication JSON de ntfy, à poster sur la racine du serveur ntfy) ;
- un e-mail par un relais SMTP (STARTTLS, TLS ou clair, authentification facultative).

Le corps ne contient que le titre de la règle, son niveau, l'appareil, le type d'événement et
l'heure : jamais le journal brut (full_log), ni les données de l'événement (position GPS,
identifiants, contenu), ni de secret. La notification part chez un tiers.
"""
import json
import smtplib
import ssl
import sys
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

CONF = "/var/ossec/etc/vigie-notify.json"


def build(alert):
    rule = alert.get("rule", {})
    data = alert.get("data", {}) or {}
    v = data.get("vigie", {}) or {}
    w = data.get("vigie_watch", {}) or {}
    level = int(rule.get("level", 0))
    desc = str(rule.get("description", "alerte Wazuh"))
    device = v.get("device_name") or w.get("device_name") or v.get("device_id") or w.get("device_id") or "?"
    lines = [desc, "", f"Gravité : niveau {level} (règle {rule.get('id', '?')})", f"Appareil : {device}"]
    if v.get("type"):
        lines.append(f"Type d'événement : {v['type']}")
    if v.get("ts"):
        lines.append(f"Heure de l'événement : {v['ts']}")
    elif w.get("last_seen"):
        lines.append(f"Dernier événement reçu : {w['last_seen']}")
    lines.append(f"Heure de l'alerte (Wazuh) : {alert.get('timestamp', '?')}")
    mitre = [g[len("attack_mobile_"):] for g in rule.get("groups", []) if g.startswith("attack_mobile_")]
    if mitre:
        lines.append("ATT&CK Mobile : " + ", ".join(mitre))
    lines += ["", "Détails : dashboard Wazuh (siem.) ou console Vigie."]
    title = f"Vigie [{level}] {desc}"
    if len(title) > 200:
        title = title[:199] + "…"
    priority = 5 if level >= 12 else 4 if level >= 10 else 3
    return title, "\n".join(lines), priority


def send_webhook(conf, title, message, priority):
    body = {"title": title, "message": message, "priority": priority, "tags": ["vigie", "rotating_light" if priority >= 5 else "warning"]}
    if conf.get("topic"):
        body["topic"] = conf["topic"]
    req = urllib.request.Request(conf["url"], data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "vigie-notify"})
    if conf.get("token"):
        req.add_header("Authorization", "Bearer " + conf["token"])
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        if r.status >= 300:
            raise RuntimeError(f"webhook : HTTP {r.status}")


def send_mail(conf, title, message):
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = conf.get("smtp_from") or conf.get("smtp_user") or "vigie@localhost"
    msg["To"] = conf["smtp_to"]
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="vigie")
    msg.set_content(message)
    mode = conf.get("smtp_tls", "starttls")
    port = int(conf.get("smtp_port") or 587)
    ctx = ssl.create_default_context()
    if mode == "tls":
        s = smtplib.SMTP_SSL(conf["smtp_host"], port, timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(conf["smtp_host"], port, timeout=20)
        if mode == "starttls":
            s.starttls(context=ctx)
    try:
        if conf.get("smtp_user"):
            s.login(conf["smtp_user"], conf.get("smtp_password", ""))
        s.send_message(msg, to_addrs=[a.strip() for a in conf["smtp_to"].split(",") if a.strip()])
    finally:
        s.quit()


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        alert = json.load(f)
    with open(CONF, encoding="utf-8") as f:
        conf = json.load(f)
    title, message, priority = build(alert)
    errors = []
    if conf.get("url"):
        try:
            send_webhook(conf, title, message, priority)
        except Exception as e:  # noqa: BLE001 — une erreur ne doit pas empêcher l'e-mail
            errors.append(f"webhook : {e}")
    if conf.get("smtp_host") and conf.get("smtp_to"):
        try:
            send_mail(conf, title, message)
        except Exception as e:  # noqa: BLE001
            errors.append(f"smtp : {e}")
    if errors:
        print("vigie-notify : " + " ; ".join(errors), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
