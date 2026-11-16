#!/usr/bin/env python3
"""Watchpost notification: Wazuh integration called by wazuh-integratord for each selected alert
(level >= WATCHPOST_NOTIFY_LEVEL, plus the agent silence). Arguments: <JSON alert file> …

Sends, according to /var/ossec/etc/watchpost-notify.json (written by watchpost-init.sh from .env):
- a simple JSON POST to a webhook: {"title", "message", "priority", "tags"} (+ "topic" if
  set: ntfy JSON publishing format, to be posted to the root of the ntfy server);
- an e-mail through an SMTP relay (STARTTLS, TLS or plain, optional authentication).

The body contains only the rule title, its level, the device, the event type and the time:
never the raw log (full_log), nor the event data (GPS position, identifiers, content), nor any
secret. The notification goes to a third party.
"""
import json
import smtplib
import ssl
import sys
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

CONF = "/var/ossec/etc/watchpost-notify.json"


def build(alert):
    rule = alert.get("rule", {})
    data = alert.get("data", {}) or {}
    v = data.get("watchpost", {}) or {}
    w = data.get("watchpost_watch", {}) or {}
    level = int(rule.get("level", 0))
    desc = str(rule.get("description", "Wazuh alert"))
    device = v.get("device_name") or w.get("device_name") or v.get("device_id") or w.get("device_id") or "?"
    lines = [desc, "", f"Severity: level {level} (rule {rule.get('id', '?')})", f"Device: {device}"]
    if v.get("type"):
        lines.append(f"Event type: {v['type']}")
    if v.get("ts"):
        lines.append(f"Event time: {v['ts']}")
    elif w.get("last_seen"):
        lines.append(f"Last event received: {w['last_seen']}")
    lines.append(f"Alert time (Wazuh): {alert.get('timestamp', '?')}")
    mitre = [g[len("attack_mobile_"):] for g in rule.get("groups", []) if g.startswith("attack_mobile_")]
    if mitre:
        lines.append("ATT&CK Mobile: " + ", ".join(mitre))
    lines += ["", "Details: Wazuh dashboard (siem.) or Watchpost console."]
    title = f"Watchpost [{level}] {desc}"
    if len(title) > 200:
        title = title[:199] + "…"
    priority = 5 if level >= 12 else 4 if level >= 10 else 3
    return title, "\n".join(lines), priority


def send_webhook(conf, title, message, priority):
    body = {"title": title, "message": message, "priority": priority, "tags": ["watchpost", "rotating_light" if priority >= 5 else "warning"]}
    if conf.get("topic"):
        body["topic"] = conf["topic"]
    req = urllib.request.Request(conf["url"], data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "watchpost-notify"})
    if conf.get("token"):
        req.add_header("Authorization", "Bearer " + conf["token"])
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        if r.status >= 300:
            raise RuntimeError(f"webhook: HTTP {r.status}")


def send_mail(conf, title, message):
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = conf.get("smtp_from") or conf.get("smtp_user") or "watchpost@localhost"
    msg["To"] = conf["smtp_to"]
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="watchpost")
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
        except Exception as e:  # noqa: BLE001 - an error must not prevent the e-mail
            errors.append(f"webhook: {e}")
    if conf.get("smtp_host") and conf.get("smtp_to"):
        try:
            send_mail(conf, title, message)
        except Exception as e:  # noqa: BLE001
            errors.append(f"smtp: {e}")
    if errors:
        print("watchpost-notify: " + "; ".join(errors), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
