#!/usr/bin/env python3
"""Génère les cas de test des règles Vigie (cases/*.log). Usage : python3 generer-cas.py cases

Chaque fichier : commentaires (description, « attendu: <id de règle> » pour la DERNIÈRE ligne),
puis une ou plusieurs lignes d'événement (les premières préparent les règles de corrélation).
@@DNS_HOST@@ est remplacé à l'exécution par l'hôte DNS privé attendu (liste CDB)."""
import json, os, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for f in os.listdir(out):
    if f.endswith('.log'): os.remove(os.path.join(out, f))
seq = [1000]
def ev(typ, data, sev=0, dev="dev_7k2m9q", name="s25", source=None):
    seq[0] += 1
    v = {"device_id": dev, "device_name": name, "id": "01JTEST%019d" % seq[0],
        "ts": "2026-11-15T21:43:03.974Z", "received_at": "2026-11-15T21:43:05.120Z", "seq": seq[0],
        "type": typ, "domain": typ.split('.')[0], "sev": sev}
    if source:  # événements produits par le collecteur (commandes §8, pistage §9, détections §11.3)
        v["seq"] = 0; v["source"] = source
    v["data"] = data
    return json.dumps({"vigie": v}, ensure_ascii=False, separators=(',', ':'))
CMD = "01JCQ8Z3K4M5N6P7Q8R9S0T1V2"
def issued(typ, params=None, sev=0, **kw):
    d = {"command_id": CMD, "type": typ, "signed": typ in ("lock", "wipe", "clear_lock_message"), "created_by": "admin",
         "expires_at": "2026-11-23T10:00:00.000Z", "params": params or {}}
    d.update(kw)
    return ev("command.issued", d, sev, source="server")
def result(typ, status, detail=None, sev=0):
    d = {"command_id": CMD, "type": typ, "status": status, "signed": typ in ("lock", "wipe", "clear_lock_message")}
    if detail: d["detail"] = detail
    return ev("command.result", d, sev)
def agh(qh, filtered=False, listid=10, ip="203.0.113.7", cp="dot"):
    d = {"T": "2026-11-15T22:30:36.905394867Z", "QH": qh, "QT": "A", "QC": "IN", "CP": cp,
         "Answer": "PjuBgAABAAEAAAAAD2FwcC1tZWFzdXJlbWVudANjb20AAAEAAcAMAAEAAQAAAAoABAAAAAA=", "IP": ip}
    if filtered:
        d["Result"] = {"Rules": [{"Text": "||%s^" % qh, "FilterListID": listid}], "Reason": 3, "IsFiltered": True}
    else:
        d["Result"] = {}; d["Upstream"] = "https://dns.quad9.net:443/dns-query"
    d["Elapsed"] = 186617
    return json.dumps(d, separators=(',', ':'))
# v1.2 : détections (contrat §11.3), applications des scénarios du simulateur
TORCH = ("com.flashlight.pro.tools", "Lampe Torche Pro")
TROJAN = ("com.android.systemupdate.service", "Mise à jour du système")
SPY = ("com.android.battery.service", "Battery Service")
VAULT = ("com.gallery.vault.hide", "Coffre Photos")
PUZZLE = ("com.puzzle.relax.free", "Puzzle Relax")
CLEANER = ("com.cleaner.boost.free", "Nettoyeur Boost")
FASTVPN = ("com.fastvpn.browser", "Navigateur Rapide")
BROWSER = ("com.sec.android.app.sbrowser", "Samsung Internet")
DAY = ("2026-11-15T00:00:00.000Z", "2026-11-16T00:00:00.000Z")
INSTALL_WINDOW = ("2026-11-15T12:42:07.204Z", "2026-11-16T12:42:07.204Z")
def det(kind, app, evidence, sev=3, update=False, window=DAY):
    d = {"evidence": evidence, "label": app[1], "package": app[0], "summary": "%s : constat de test (%s)" % (app[1], kind),
         "window_from": window[0], "window_to": window[1]}
    if update:
        d["update"] = True; d["detection_id"] = "01M7JPAP1R31CWDX8J7CFDY1M7"
    return ev("detect." + kind, d, sev, source="server")
def newapp(caps, high, reasons, score, level="high"):
    e = {"capabilities": caps, "from_store": False, "high_risk": high, "installed_at": INSTALL_WINDOW[0],
         "installer": "com.google.android.packageinstaller", "level": level, "reasons": reasons, "score": score}
    if caps:
        e["minutes_to_first_capability"] = 3
    return e
def risk(app, level, score, reasons, installer, vc=7):
    return ev("app.risk", {"from_store": installer in ("com.android.vending", "com.sec.android.app.samsungapps"), "installer": installer,
        "label": app[1], "level": level, "package": app[0], "reasons": reasons, "score": score, "version_code": vc},
        {"low": 0, "medium": 1, "high": 2}[level])
def guard(action, key, target, permission=None, sev=None, ok=True):
    d = {"action": action, "ok": ok, "profile": "guard:" + key, "target": target}
    if permission: d["permission"] = permission
    if not ok: d["error"] = "SecurityException"
    return ev("security.policy", d, 1 if sev is None else sev)
def pc(field, old, new, sev=0):
    return ev("security.posture_change", {"field": field, "old": old, "new": new}, sev)
def watch(o):
    return json.dumps({"vigie_watch": o}, separators=(',', ':'))
GOOD = {"security_patch": "2026-10-01", "patch_age_days": 45, "encrypted": True, "lock_secure": True,
        "adb_enabled": False, "adb_wifi_enabled": False, "dev_options": False, "unknown_sources": False,
        "private_dns_mode": "hostname", "private_dns_host": "@@DNS_HOST@@", "always_on_vpn": False,
        "device_owner": True, "verified_boot_state": "green", "user_ca_certs": [], "play_protect": True,
        "usb_data_signaling": True}
def posture(**kw):
    d = dict(GOOD); d.update(kw); return ev("security.posture", d)
SA = {"accessibility_services": [], "notification_listeners": ["com.google.android.gms/.NotifListener"],
      "device_admins": ["io.github.erwsim.vigie/.AdminReceiver"], "overlay_apps": [], "unknown_sources_apps": [],
      "usage_access_apps": ["io.github.erwsim.vigie"], "vpn_apps": [], "default_apps": {"browser": "org.mozilla.firefox"}}
def sa(**kw):
    d = dict(SA); d.update(kw); return ev("app.special_access", d)
def slog(tag, fields=None, level="info"):
    return ev("security.log", {"tag": tag, "level": level, "log_id": 12345, "fields": fields or {}})
H = "15b9d7d0c1f9e0a3b8f6c2d4e5a7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"
cases = [
 ("100100", "evenement-ordinaire", "Position normale : règle de base, niveau 0", [ev("location.fix", {"lat": 48.8566, "lon": 2.3522, "acc_m": 12.5, "provider": "gps", "mock": False, "fix_ts": "2026-11-15T21:43:03Z", "location": {"lat": 48.8566, "lon": 2.3522}})]),
 ("100101", "ligne-derivee-inventaire", "Élément d'inventaire (ligne dérivée de l'export)", [ev("app.inventory.app", {"package": "org.mozilla.firefox", "installer": "com.android.vending", "system": False, "part": 1, "parts": 3})]),
 ("100110", "agent-alteration", "Altération de l'agent", [ev("agent.tamper", {"kind": "permission_revoked", "detail": "ACCESS_FINE_LOCATION"}, 3)]),
 ("100111", "agent-arret", "Arrêt de l'agent", [ev("agent.stopped", {"reason": "user", "agent_version": "1.0.0"})]),
 ("100112", "agent-tampon-sature", "Purge du tampon", [ev("agent.buffer_overflow", {"dropped": 1200, "oldest_ts": "2026-10-01T00:00:00Z", "newest_ts": "2026-10-03T00:00:00Z"}, 2)]),
 ("100113", "agent-erreur-collecteur", "Erreur d'un collecteur", [ev("agent.collector_error", {"collector": "net.cell", "error": "SecurityException"}, 1)]),
 ("100114", "agent-reglage", "Réglage modifié (anodin)", [ev("agent.config_changed", {"key": "ui.theme", "old": "light", "new": "dark"})]),
 ("100115", "agent-collecte-desactivee", "Collecte désactivée dans l'agent", [ev("agent.config_changed", {"key": "collector.location.enabled", "old": True, "new": False}, 1)]),
 ("100116", "agent-perte-device-owner", "Battement sans Device Owner", [ev("agent.heartbeat", {"battery_pct": 80, "charging": False, "uptime_ms": 360000, "queue_depth": 0, "queue_bytes": 0, "dropped_total": 0, "device_owner": False, "collectors": {"location": "running", "net.dns": "unavailable"}, "last_upload_ts": "2026-11-15T21:40:00Z"}, 1)]),
 ("100100", "agent-battement-normal", "Battement normal (Device Owner) : pas d'alerte", [ev("agent.heartbeat", {"battery_pct": 80, "charging": True, "device_owner": True, "collectors": {"location": "running"}})]),
 ("100120", "horloge-modifiee", "Changement d'heure de 2 h", [ev("device.time_changed", {"delta_ms": -7200000}, 1)]),
 ("100100", "horloge-derive-faible", "Correction d'horloge de 1,5 s : pas d'alerte", [ev("device.time_changed", {"delta_ms": 1500})]),
 ("100121", "usb-adb", "USB avec ADB", [ev("device.usb", {"connected": True, "configured": True, "functions": ["mtp", "adb"]}, 1)]),
 ("100130", "position-simulee", "Position simulée", [ev("location.fix", {"lat": 48.85, "lon": 2.35, "acc_m": 3, "provider": "gps", "mock": True, "location": {"lat": 48.85, "lon": 2.35}}, 2)]),
 ("100140", "cellulaire-autre", "Anomalie cellulaire non classée", [ev("net.cell_security", {"kind": "other", "detail": "x"}, 2)]),
 ("100141", "cellulaire-2g", "Rétrogradation 2G", [ev("net.cell_security", {"kind": "downgrade_2g", "detail": "LTE->GSM"}, 2)]),
 ("100142", "cellulaire-chiffrement-nul", "Chiffrement nul", [ev("net.cell_security", {"kind": "null_cipher", "detail": "A5/0"}, 3)]),
 ("100143", "cellulaire-imsi", "Divulgation d'identifiant", [ev("net.cell_security", {"kind": "identifier_disclosure", "detail": "IMSI"}, 2)]),
 ("100145", "traceur-ble", "Traceur BLE qui suit l'appareil", [ev("net.ble_tracker", {"address": "c4:5a:11:22:33:44", "kind": "airtag", "rssi": -60, "first_seen": "2026-11-15T19:00:00Z", "sightings": 14}, 2)]),
 ("100146", "wifi-ouvert", "Wi-Fi ouvert", [ev("net.wifi", {"event": "connected", "ssid": "Gare-WiFi", "bssid": "aa:bb:cc:dd:ee:ff", "rssi": -50, "freq_mhz": 2437, "security": "open"})]),
 ("100100", "wifi-wpa3", "Wi-Fi WPA3 : pas d'alerte", [ev("net.wifi", {"event": "connected", "ssid": "Maison", "security": "wpa3"})]),
 ("100147", "reseau-sans-dns-prive", "Réseau sans DNS privé", [ev("net.connectivity", {"transports": ["wifi"], "validated": True, "metered": False, "vpn": False, "private_dns_active": False, "dns_servers": ["192.168.1.1"]})]),
 ("100148", "dns-telemetrie", "Requête d'une app vers un domaine de télémétrie", [ev("net.dns", {"package": "com.example.game", "uid": 10234, "hostname": "app-measurement.com", "addresses": ["0.0.0.0"], "address_count": 1})]),
 ("100148", "dns-telemetrie-samsung", "Requête vers la télémétrie Samsung", [ev("net.dns", {"package": "com.samsung.android.game.gos", "hostname": "api.gos-gsp.io", "address_count": 0})]),
 ("100100", "dns-ordinaire", "Requête DNS ordinaire", [ev("net.dns", {"package": "org.mozilla.firefox", "hostname": "example.org", "address_count": 2})]),
 ("100150", "app-installee-play", "App installée depuis le Play Store", [ev("app.installed", {"package": "org.example.app", "version_name": "1.2", "version_code": 12, "installer": "com.android.vending", "signer_sha256": H})]),
 ("100151", "app-installee-hors-store", "App installée par un autre installateur", [ev("app.installed", {"package": "org.example.apk", "version_name": "1.0", "version_code": 1, "installer": "com.google.android.packageinstaller", "signer_sha256": H}, 1)]),
 ("100152", "app-installee-adb", "App installée sans installateur (ADB)", [ev("app.installed", {"package": "org.example.adb", "version_name": "1.0", "version_code": 1, "signer_sha256": H}, 1)]),
 ("100153", "app-desinstallee", "App désinstallée", [ev("app.removed", {"package": "org.example.app"})]),
 ("100155", "acces-speciaux-quotidien", "Accès spéciaux inchangés (un seul événement)", [sa()]),
 ("100156", "acces-accessibilite", "Nouvelle app avec service d'accessibilité", [sa(), sa(accessibility_services=["com.evil.app/.A11yService"])]),
 ("100157", "acces-admin-appareil", "Nouvel administrateur de l'appareil", [sa(), sa(device_admins=["io.github.erwsim.vigie/.AdminReceiver", "com.evil.app/.Admin"])]),
 ("100158", "acces-notifications", "Nouvelle app qui lit les notifications", [sa(), sa(notification_listeners=["com.google.android.gms/.NotifListener", "com.evil.app/.Listener"])]),
 ("100159", "acces-vpn", "Nouvelle app VPN", [sa(), sa(vpn_apps=["com.evil.vpn"])]),
 ("100155", "acces-speciaux-identiques", "Deux états identiques : pas d'alerte", [sa(), sa()]),
 ("100160", "permission-micro", "Permission micro accordée", [ev("app.permission_changed", {"package": "com.example.voice", "permission": "android.permission.RECORD_AUDIO", "granted": True})]),
 ("100100", "permission-retiree", "Permission retirée : pas d'alerte", [ev("app.permission_changed", {"package": "com.example.voice", "permission": "android.permission.RECORD_AUDIO", "granted": False})]),
 ("100170", "micro-utilise", "Micro utilisé", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.whatsapp", "silenced": False, "screen_on": True, "locked": False})]),
 ("100171", "camera-utilisee", "Caméra utilisée", [ev("sensor.camera", {"camera_id": "1", "in_use": True, "package": "com.whatsapp", "screen_on": True, "locked": False})]),
 ("100180", "deverrouillage-echoue", "Un échec de déverrouillage", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": 1}, 1)]),
 ("100181", "deverrouillages-repetes", "5 échecs en moins de 10 min", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": n}, 1) for n in range(1, 6)]),
 ("100182", "deverrouillages-consecutifs", "12 échecs consécutifs signalés", [ev("security.keyguard", {"event": "unlock_failed", "failed_attempts": 12}, 2)]),
 ("100185", "ac-ajoutee", "AC utilisateur ajoutée", [ev("security.ca_cert", {"event": "added", "sha256": H, "subject": "CN=Proxy MITM"}, 2)]),
 ("100186", "ac-retiree", "AC utilisateur retirée", [ev("security.ca_cert", {"event": "removed", "sha256": H, "subject": "CN=Proxy MITM"}, 2)]),
 ("100187", "politique-echec", "Échec d'une action Device Owner", [ev("security.policy", {"action": "package_disabled", "target": "com.samsung.android.bixby.agent", "profile": "equilibre", "ok": False, "error": "SecurityException"}, 1)]),
 ("100100", "politique-ok", "Action Device Owner réussie : pas d'alerte", [ev("security.policy", {"action": "private_dns_set", "target": "@@DNS_HOST@@", "profile": "equilibre", "ok": True})]),
 ("100190", "posture-saine", "Posture saine : pas d'alerte", [posture()]),
 ("100191", "posture-boot-orange", "Démarrage vérifié orange", [posture(verified_boot_state="orange", adb_enabled=True)]),
 ("100192", "posture-non-chiffre", "Stockage non chiffré", [posture(encrypted=False)]),
 ("100193", "posture-pas-device-owner", "Pas Device Owner", [posture(device_owner=False)]),
 ("100194", "posture-dns-prive-off", "DNS privé désactivé", [posture(private_dns_mode="off", private_dns_host=None)]),
 ("100194", "posture-dns-prive-auto", "DNS privé automatique (non strict)", [posture(private_dns_mode="opportunistic", private_dns_host=None)]),
 ("100195", "posture-dns-prive-autre-hote", "DNS privé vers un autre hôte", [posture(private_dns_host="dns.adguard-dns.com")]),
 ("100196", "posture-adb-wifi", "ADB sans fil", [posture(adb_wifi_enabled=True, adb_enabled=True, dev_options=True)]),
 ("100197", "posture-adb", "ADB activé", [posture(adb_enabled=True, dev_options=True)]),
 ("100198", "posture-sans-verrouillage", "Pas de verrouillage sécurisé", [posture(lock_secure=False)]),
 ("100199", "posture-ac-utilisateur", "AC utilisateur présente", [posture(user_ca_certs=[H])]),
 ("100200", "posture-correctif-6-mois", "Correctif de plus de 6 mois", [posture(patch_age_days=200)]),
 ("100201", "posture-sources-inconnues", "Sources inconnues autorisées", [posture(unknown_sources=True)]),
 ("100202", "posture-correctif-3-mois", "Correctif de plus de 3 mois", [posture(patch_age_days=120)]),
 ("100203", "posture-play-protect", "Play Protect désactivé", [posture(play_protect=False)]),
 ("100204", "posture-options-dev", "Options développeur", [posture(dev_options=True)]),
 ("100210", "journal-securite-ordinaire", "Journal de sécurité ordinaire", [slog("app_process_start", {"process": "com.android.chrome", "start_time": 1794774875127, "uid": 10100, "pid": 30412, "seinfo": "default:targetSdkVersion=35:complete", "apk_sha256": H})]),
 ("100211", "journal-adb-shell", "Shell ADB interactif", [slog("adb_shell_interactive")]),
 ("100212", "journal-adb-commande", "Commande ADB", [slog("adb_shell_cmd", {"command": "pm list packages"})]),
 ("100213", "journal-adb-fichier", "Transfert de fichier ADB", [slog("sync_recv_file", {"path": "/sdcard/DCIM/x.jpg"})]),
 ("100214", "journal-keyguard-echec", "Échec d'authentification (journal)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "strength": 1})]),
 ("100215", "journal-keyguard-repetes", "5 échecs (journal)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "strength": 1}) for _ in range(5)]),
 ("100216", "journal-ac-installee", "AC installée (journal)", [slog("cert_authority_installed", {"success": True, "subject": "CN=Proxy MITM", "user_id": 0})]),
 ("100217", "journal-arrete", "Journalisation arrêtée", [slog("logging_stopped")]),
 ("100218", "journal-tampon-critique", "Tampon du journal presque plein", [slog("log_buffer_size_critical")]),
 ("100219", "journal-violation-cle", "Violation d'intégrité de clé", [slog("key_integrity_violation", {"alias": "vigie_upload_key", "uid": 10301})]),
 ("100220", "journal-autotest-crypto", "Échec de l'autotest crypto", [slog("crypto_self_test_completed", {"success": False})]),
 ("100221", "journal-effacement-echec", "Échec d'effacement", [slog("wipe_failure", {"arg0": "x"})]),
 ("100222", "journal-restriction-retiree", "Restriction utilisateur retirée", [slog("user_restriction_removed", {"admin_package": "io.github.erwsim.vigie", "user_id": 0, "restriction": "no_debugging_features"})]),
 ("100223", "journal-support-monte", "Support amovible monté", [slog("media_mount", {"mount_point": "/storage/ABCD-1234", "label": "USB"})]),
 ("100224", "journal-validation-certificat", "Échec de validation de certificat", [slog("cert_validation_failure", {"reason": "untrusted"})]),
 ("100300", "sonde-autre", "Sonde : constat inconnu", [watch({"check": "other", "device_id": "dev_7k2m9q"})]),
 ("100301", "sonde-silence", "Appareil silencieux", [watch({"check": "silence", "device_id": "dev_7k2m9q", "device_name": "s25", "last_seen": "2026-11-15T20:00:00Z", "silence_min": 95, "threshold_min": 60})]),
 ("100302", "sonde-reprise", "Appareil de nouveau actif", [watch({"check": "resumed", "device_id": "dev_7k2m9q", "device_name": "s25", "last_seen": "2026-11-15T22:00:00Z"})]),
 ("100303", "sonde-trou-sequence", "Trou de séquence inexpliqué", [watch({"check": "seq_gap", "device_id": "dev_7k2m9q", "device_name": "s25", "missing_count": 3, "first_missing": 120, "last_missing": 122, "sample": [120, 121, 122], "explained": "none"})]),
 ("100304", "sonde-trou-explique", "Trou de séquence dû à la purge du tampon", [watch({"check": "seq_gap", "device_id": "dev_7k2m9q", "device_name": "s25", "missing_count": 300, "first_missing": 120, "last_missing": 419, "sample": [120], "explained": "buffer_overflow"})]),
 ("100305", "sonde-sequence-remise-a-zero", "Compteur de séquence revenu en arrière", [watch({"check": "seq_reset", "device_id": "dev_7k2m9q", "device_name": "s25", "previous_max_seq": 18234, "current_max_seq": 12})]),
 ("100290", "rotation-export", "Rotation par renommage de l'export : pas d'alerte", ["ossec: File rotated (inode changed): '/var/vigie/events.ndjson'."]),
 ("100290", "rotation-adguard", "Rotation du journal AdGuard : pas d'alerte", ["ossec: File rotated (inode changed): '/var/adguard/querylog.json'."]),
 ("591", "rotation-autre-fichier", "Rotation d'un autre fichier : règle Wazuh 591 conservée", ["ossec: File rotated (inode changed): '/var/log/autre.log'."]),
 ("100172", "micro-appareil-verrouille", "Micro utilisé appareil verrouillé", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.qrscan.free.reader", "silenced": False, "screen_on": False, "locked": True}, 2)]),
 ("100173", "micro-ecran-eteint-hors-appel", "Micro utilisé écran éteint hors appel", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.example.recorder", "silenced": False, "screen_on": False, "locked": False})]),
 ("100170", "micro-appel-ecran-eteint", "Appel : écran éteint par le capteur de proximité, pas d'alerte", [ev("sensor.microphone", {"recording": True, "source": "voice_communication", "package": "com.whatsapp", "silenced": False, "screen_on": False, "locked": False})]),
 ("100174", "camera-appareil-verrouille", "Caméra utilisée appareil verrouillé", [ev("sensor.camera", {"camera_id": "1", "in_use": True, "package": "com.qrscan.free.reader", "screen_on": False, "locked": True}, 2)]),
 ("100175", "camera-ecran-eteint", "Caméra utilisée écran éteint", [ev("sensor.camera", {"camera_id": "0", "in_use": True, "package": "com.example.app", "screen_on": False, "locked": False})]),
 ("100250", "posture-change-autre", "Changement de posture sans gravité (retour à la normale)", [pc("adb_enabled", "true", "false")]),
 ("100251", "posture-change-adb-wifi", "ADB sans fil activé", [pc("adb_wifi_enabled", "false", "true", 2)]),
 ("100252", "posture-change-adb", "ADB activé", [pc("adb_enabled", "false", "true", 2)]),
 ("100253", "posture-change-options-dev", "Options développeur activées", [pc("dev_options", "false", "true", 2)]),
 ("100254", "posture-change-sources-inconnues", "Sources inconnues autorisées", [pc("unknown_sources", "false", "true", 2)]),
 ("100255", "posture-change-device-owner", "Perte du Device Owner", [pc("device_owner", "true", "false", 3)]),
 ("100256", "posture-change-chiffrement", "Chiffrement perdu", [pc("encrypted", "true", "false", 3)]),
 ("100257", "posture-change-verrouillage", "Verrouillage sécurisé supprimé", [pc("lock_secure", "true", "false", 3)]),
 ("100258", "posture-change-play-protect", "Play Protect désactivé", [pc("play_protect", "true", "false", 2)]),
 ("100259", "posture-change-demarrage-verifie", "Démarrage vérifié dégradé", [pc("verified_boot_state", "green", "orange", 3)]),
 ("100260", "posture-change-dns-prive-auto", "DNS privé passé en automatique", [pc("private_dns_mode", "hostname", "opportunistic", 2)]),
 ("100260", "posture-change-dns-prive-off", "DNS privé désactivé", [pc("private_dns_mode", "hostname", "off", 2)]),
 ("100261", "posture-change-dns-hote", "Hôte DNS privé modifié", [pc("private_dns_host", "@@DNS_HOST@@", "dns.adguard-dns.com", 2)]),
 ("100250", "posture-change-dns-hote-attendu", "Hôte DNS privé rétabli : pas d'alerte spécifique", [pc("private_dns_host", "", "@@DNS_HOST@@")]),
 ("100264", "posture-change-dns-hote-vide", "Hôte DNS privé vidé (marqué ; le mode non strict est alerté par 100260)", [pc("private_dns_host", "@@DNS_HOST@@", "")]),
 ("100262", "posture-change-ac-utilisateur", "AC utilisateur ajoutée (marquée ; alerte portée par security.ca_cert)", [pc("user_ca_certs", "", H, 2)]),
 ("100265", "posture-change-ac-retirees", "AC utilisateur retirées (marqué ; alerté par security.ca_cert)", [pc("user_ca_certs", H, "")]),
 ("100263", "posture-change-correctif", "Correctif de sécurité installé", [pc("security_patch", "2026-10-01", "2026-11-01")]),
 ("100225", "journal-demarrage-orange", "Démarrage avec état orange (marqué)", [slog("os_startup", {"verified_boot_state": "orange", "dm_verity_mode": "enforcing"})]),
 ("100226", "journal-dm-verity", "dm-verity non appliqué", [slog("os_startup", {"verified_boot_state": "green", "dm_verity_mode": "eio"})]),
 ("100210", "journal-demarrage-normal", "Démarrage normal : pas d'alerte", [slog("os_startup", {"verified_boot_state": "green", "dm_verity_mode": "enforcing"})]),
 ("100227", "journal-code-modifie", "Code de verrouillage modifié", [slog("password_changed", {"complexity": 196608, "user_id": 0})]),
 ("100228", "journal-cle-echec", "Échec de génération de clé", [slog("key_generated", {"success": False, "alias": "vigie_upload_key", "uid": 10301})]),
 ("100105", "severite-critique-type-inconnu", "Type inconnu, sévérité 3", [ev("device.unknown_future_type", {"x": 1}, 3)]),
 ("100106", "severite-avertissement-type-inconnu", "Type inconnu, sévérité 2", [ev("net.unknown_future_type", {"x": 1}, 2)]),
 ("100400", "adguard-requete", "Requête DNS non bloquée", [agh("example.org")]),
 ("100401", "adguard-bloquee", "Requête DNS bloquée", [agh("app-measurement.com", True, 1)]),
 ("100402", "adguard-menace", "Domaine du flux de menaces", [agh("malware.example", True, 30)]),
 ("100403", "adguard-rafale", "60 requêtes bloquées en rafale", [agh("ads%d.example" % i, True, 10) for i in range(60)]),
 ("100404", "adguard-menaces-repetees", "5 domaines malveillants", [agh("c2-%d.example" % i, True, 30) for i in range(5)]),
 # --- Commandes à distance (v1.1, contrat §8) et notifications (§10)
 ("100230", "commande-emise-sonnerie", "Commande simple émise (sonner)", [issued("ring", {"duration_s": 60, "vibrate": True})]),
 ("100231", "commande-emise-localiser", "Localisation à distance demandée", [issued("locate")]),
 ("100232", "commande-emise-verrouillage", "Verrouillage à distance demandé (message non exporté)", [issued("lock", {}, 1, message_set=True)]),
 ("100233", "commande-emise-effacement", "Effacement à distance demandé", [issued("wipe", {}, 2)]),
 ("100234", "commande-emise-retrait-message", "Retrait du message de verrouillage demandé", [issued("clear_lock_message", {}, 1)]),
 ("100100", "commande-emise-imitee", "command.issued envoyé par un appareil (sans source serveur) : aucune alerte", [ev("command.issued", {"command_id": CMD, "type": "wipe", "signed": True, "created_by": "admin"}, 2)]),
 ("100235", "commandes-rafale", "8 commandes en 10 min vers le même appareil", [issued("lock", {}, 1, message_set=False)] + [issued("ring", {"duration_s": 5}) for _ in range(7)]),
 ("100236", "commande-annulee", "Commande annulée", [ev("command.cancelled", {"command_id": CMD, "type": "ring", "signed": False, "cancelled_by": "admin"}, source="server")]),
 ("100237", "commande-expiree", "Commande simple expirée", [ev("command.expired", {"command_id": CMD, "type": "ring", "signed": False, "delivered": False}, 1, source="server")]),
 ("100238", "commande-sensible-expiree", "Verrouillage expiré sans résultat", [ev("command.expired", {"command_id": CMD, "type": "lock", "signed": True, "delivered": True}, 1, source="server")]),
 ("100239", "commande-resultat-api", "Résultat reçu par l'API (marqué seulement)", [ev("command.reported", {"command_id": CMD, "type": "lock", "status": "refused", "detail": "bad_signature", "signed": True, "agent_at": "2026-11-16T10:00:01.000Z"}, 3, source="server")]),
 ("100240", "commande-resultat-simple", "Sonnerie exécutée", [result("ring", "executed")]),
 ("100241", "commande-resultat-verrouillage", "Verrouillage exécuté par le téléphone", [result("lock", "executed", None, 2)]),
 ("100242", "commande-resultat-effacement", "Effacement exécuté par le téléphone", [result("wipe", "executed", None, 2)]),
 ("100243", "commande-refusee", "Commande refusée (expirée)", [result("lock", "refused", "expired", 1)]),
 ("100244", "commande-signature-invalide", "Signature invalide (sévérité 3 : pas de repli 100105)", [result("lock", "refused", "bad_signature", 3)]),
 ("100245", "commande-canal-verrouille", "Canal des commandes sensibles verrouillé", [result("wipe", "refused", "locked_out", 3)]),
 ("100246", "commande-rejouee", "Refus replay (renvoi normal)", [result("ring", "refused", "replay", 1)]),
 ("100247", "commande-echec", "Commande échouée", [result("lock", "failed", "not_device_owner", 1)]),
 ("100270", "notification-avec-contenu", "Notification avec titre et texte (jamais dans la description)", [ev("app.notification", {"package": "org.thoughtcrime.securesms", "event": "posted", "category": "msg", "channel": "messages", "ongoing": False, "importance": "high", "title": "Alice <script>\"'", "text": "Ton code est 123456 — « secret » \\ ligne\nsuivante", "redacted": True})]),
 ("100270", "notification-retiree", "Notification retirée (sans contenu)", [ev("app.notification", {"package": "com.whatsapp", "event": "removed", "category": "msg", "channel": "c", "ongoing": False, "importance": "default"})]),
 ("100233", "commandes-rafale-effacement", "Rafale terminée par un effacement : l'alerte d'effacement n'est pas masquée", [issued("ring", {"duration_s": 5}) for _ in range(7)] + [issued("wipe", {}, 2)]),
 # --- v1.2 : détections du collecteur (contrat §11.3 ; formes relevées dans l'export réel du collecteur)
 ("100460", "detection-domaine-menace", "Application qui contacte des domaines de menaces (sév. 3)", [det("threat_domain", TROJAN, {"blocked": 21, "domain_count": 2, "domains": ["api.secure-bank-sync.example", "gate.cdn-update-check.example"], "lists": ["HaGeZi Threat Intelligence Feeds (medium)"], "requests": 96})]),
 ("100461", "detection-domaine-menace-navigateur", "Navigateur qui a suivi un lien d'hameçonnage (sév. 2)", [det("threat_domain", BROWSER, {"blocked": 1, "domain_count": 1, "domains": ["login-banque.phish.example"], "lists": ["HaGeZi Threat Intelligence Feeds (medium)"], "requests": 1}, 2)]),
 ("100462", "detection-fraude-sms", "Envoi de SMS par une appli qui n'est pas l'appli SMS", [det("sms_abuse", TORCH, {"background": 860, "default_sms_app": ["com.samsung.android.messaging"], "read_contacts": 11, "reason": "not_default_sms_app", "rejected": 0, "sent": 860})]),
 ("100463", "detection-micro-arriere-plan", "Micro et caméra en arrière-plan (le micro l'emporte)", [det("sensor_background", SPY, {"camera_background": 3, "camera_count": 3, "microphone_background": 44, "microphone_count": 44, "ops": ["record_audio", "camera"]}, 2)]),
 ("100464", "detection-camera-arriere-plan", "Caméra seule en arrière-plan", [det("sensor_background", SPY, {"camera_background": 5, "camera_count": 5, "ops": ["camera"]}, 2)]),
 ("100465", "detection-pic-envoi", "Pic d'envoi isolé (sév. 2, niveau modéré)", [det("upload_spike", VAULT, {"first_hour": "2026-11-16T16:00:00.000Z", "history_hours": 26, "hours": 1, "learning": True, "peak_hour": "2026-11-16T16:00:00.000Z", "screen_on_minutes": 6, "threshold_bytes": 1073741824, "tx_bytes": 3743416320}, 2)]),
 ("100466", "detection-eventail", "Centaines d'adresses en une heure (proxy résidentiel)", [det("fanout", PUZZLE, {"addresses": 476, "connections": 476, "first_hour": "2026-11-16T00:00:00.000Z", "hours": 5, "peak_hour": "2026-11-16T01:00:00.000Z", "ports": [443, 80, 8080], "sample": ["31.15.28.24", "31.19.75.243"], "screen_on_minutes": 0, "threshold": 100}, 2)]),
 ("100467", "detection-ports-courriel", "Connexion SMTP d'une appli ordinaire (sév. 2)", [det("mail_ports", CLEANER, {"addresses": 1, "connections": 2, "ports": [587], "sample": ["64.5.242.51"]}, 2)]),
 ("100468", "detection-spam", "Volume de spam (sév. 3)", [det("mail_ports", CLEANER, {"addresses": 347, "connections": 676, "ports": [587, 25], "sample": ["64.5.242.51", "64.36.183.25", "64.37.161.91"]})]),
 ("100469", "detection-contournement-dns", "Résolveur DoH/DoT public utilisé", [det("dns_bypass", FASTVPN, {"connections": 70, "providers": ["Cloudflare DNS", "Google Public DNS"], "resolvers": ["1.0.0.1:443", "8.8.8.8:853", "[2606:4700:4700::1111]:443"]}, 2)]),
 ("100470", "detection-nouvelle-app-capacites-grave", "Appli récente à risque (combo) qui obtient l'envoi de SMS", [det("new_app_risky", TORCH, newapp(["permission:SEND_SMS"], True, ["sideloaded", "sms_send", "boot_receiver", "combo_sms_fraud"], 91), 3, window=INSTALL_WINDOW)]),
 ("100471", "detection-nouvelle-app-capacites", "Appli récente qui obtient l'accessibilité (sév. 2)", [det("new_app_risky", ("com.example.helper", "Assistant Plus"), newapp(["accessibility"], False, ["accessibility_service"], 25, level="low"), 2, window=INSTALL_WINDOW)]),
 ("100472", "detection-nouvelle-app-vpn", "Appli récente qui devient VPN (sév. 1)", [det("new_app_risky", FASTVPN, newapp(["vpn"], False, ["vpn_service"], 20, level="low"), 1, window=INSTALL_WINDOW)]),
 ("100473", "detection-nouvelle-app-risque-seul", "Risque élevé sans capacité : déjà alerté par app.risk (marqué)", [det("new_app_risky", TROJAN, newapp([], True, ["sideloaded", "accessibility_service", "overlay", "combo_banking_trojan"], 95), 3, window=INSTALL_WINDOW)]),
 ("100474", "detection-nouvelle-app-risque-seul-sev2", "Risque élevé (sans combo) sans capacité (marqué)", [det("new_app_risky", ("com.parental.ctrl", "Contrôle parental"), newapp([], True, ["no_launcher_icon", "background_location", "boot_receiver"], 65), 2, window=INSTALL_WINDOW)]),
 ("100450", "detection-type-inconnu", "Type de détection sans règle dédiée", [det("future_kind", PUZZLE, {"x": 1}, 2)]),
 ("100100", "detection-imitee", "detect.* envoyé par un appareil (sans source serveur) : aucune alerte", [ev("detect.sms_abuse", {"package": "com.flashlight.pro.tools", "label": "Lampe Torche Pro", "evidence": {"sent": 1}}, 3)]),
 ("100451", "detection-mise-a-jour", "Mise à jour d'une détection déjà grave (nouveau domaine) : pas de seconde alerte grave", [det("threat_domain", TROJAN, {"domains": ["a.example"], "domain_count": 1, "requests": 5, "blocked": 5, "lists": ["TIF"]}), det("threat_domain", TROJAN, {"domains": ["a.example", "b.example"], "domain_count": 2, "requests": 9, "blocked": 9, "lists": ["TIF"]}, update=True)]),
 ("100453", "detection-mise-a-jour-sev2", "Mise à jour d'une détection de sévérité 2", [det("fanout", PUZZLE, {"addresses": 320, "ports": [443]}, 2), det("fanout", PUZZLE, {"addresses": 480, "ports": [443, 8080]}, 2, update=True)]),
 ("100452", "detection-aggravee", "Détection de sévérité 2 mise à jour en sévérité 3 (aggravation)", [det("mail_ports", CLEANER, {"addresses": 2, "connections": 3, "ports": [587]}, 2), det("mail_ports", CLEANER, {"addresses": 25, "connections": 140, "ports": [587, 25]}, 3, update=True)]),
 ("100489", "detection-correlation", "Deux types de détection pour la même application en 24 h", [det("sms_abuse", TORCH, {"reason": "not_default_sms_app", "sent": 860, "rejected": 0, "background": 860}), det("threat_domain", TORCH, {"domains": ["panel.sms-gateway-pay.example"], "domain_count": 1, "requests": 40, "blocked": 40, "lists": ["TIF"]})]),
 ("100460", "detection-correlation-autre-app", "Deux détections pour deux applications différentes : pas de corrélation", [det("sms_abuse", TORCH, {"reason": "volume", "sent": 300}), det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1, "requests": 4, "blocked": 4, "lists": ["TIF"]})]),
 ("100460", "detection-correlation-meme-type", "Même type deux jours de suite : pas de corrélation", [det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1}), det("threat_domain", TROJAN, {"domains": ["c2.example"], "domain_count": 1}, window=("2026-11-16T00:00:00.000Z", "2026-11-17T00:00:00.000Z"))]),
 # --- v1.2 : profil de risque, rôles, opérations (§11.2)
 ("100500", "risque-faible", "Profil de risque faible : marqué, pas d'alerte", [risk(("com.google.android.gms", "Services Google Play"), "low", 0, [], "com.android.vending", 254432035)]),
 ("100500", "risque-moyen", "Profil de risque moyen : marqué", [risk(("com.qrscan.free.reader", "QR Scanner"), "medium", 35, ["sideloaded", "unknown_installer"], "com.google.android.packageinstaller")]),
 ("100501", "risque-eleve-hors-installation", "Risque élevé sans installation récente (mise à jour)", [risk(("com.parental.ctrl", "Contrôle parental"), "high", 65, ["no_launcher_icon", "background_location", "boot_receiver"], "com.android.vending")]),
 ("100502", "risque-eleve-installation", "Application à risque élevé installée", [ev("app.installed", {"package": "com.parental.ctrl", "version_name": "3.1", "version_code": 31, "installer": "com.android.vending", "signer_sha256": H}), risk(("com.parental.ctrl", "Contrôle parental"), "high", 65, ["no_launcher_icon", "background_location", "boot_receiver"], "com.android.vending")]),
 ("100503", "risque-combo-installation", "Application au profil de logiciel malveillant installée", [ev("app.installed", {"package": TORCH[0], "version_name": "1.0", "version_code": 7, "installer": "com.google.android.packageinstaller", "signer_sha256": H}, 1), risk(TORCH, "high", 91, ["sideloaded", "unknown_installer", "no_launcher_icon", "sms_send", "boot_receiver", "combo_sms_fraud"], "com.google.android.packageinstaller")]),
 ("100501", "risque-eleve-autre-installation", "Installation d'une autre application : pas de corrélation", [ev("app.installed", {"package": "org.example.app", "version_name": "1", "version_code": 1, "installer": "com.android.vending", "signer_sha256": H}), risk(("com.parental.ctrl", "Contrôle parental"), "high", 65, ["boot_receiver"], "com.android.vending")]),
 ("100511", "role-sms", "Nouvelle appli SMS par défaut", [ev("app.role", {"role": "sms", "old": "com.samsung.android.messaging", "new": TORCH[0]}, 2)]),
 ("100512", "role-telephone", "Nouvelle appli de téléphone par défaut", [ev("app.role", {"role": "dialer", "old": "com.samsung.android.dialer", "new": "com.truecaller"}, 2)]),
 ("100513", "role-clavier", "Nouveau clavier par défaut", [ev("app.role", {"role": "keyboard", "old": "com.samsung.android.honeyboard", "new": "com.keyboard.themes.free"}, 2)]),
 ("100514", "role-assistant", "Nouvel assistant par défaut", [ev("app.role", {"role": "assistant", "old": "com.google.android.googlequicksearchbox", "new": "com.example.assistant"}, 2)]),
 ("100510", "role-navigateur", "Nouveau navigateur par défaut (information)", [ev("app.role", {"role": "browser", "old": "com.sec.android.app.sbrowser", "new": "org.mozilla.firefox"}, 1)]),
 ("100510", "role-sms-inconnu", "Rôle SMS devenu illisible (new absent) : information", [ev("app.role", {"role": "sms", "old": "com.samsung.android.messaging"}, 2)]),
 ("100520", "operations-app", "app.ops.app ordinaire : marqué", [ev("app.ops.app", {"background_count": 3, "count": 8, "from": "2026-11-13T17:00:00Z", "last_ts": "2026-11-13T17:33:32.227Z", "op": "fine_location", "package": "com.google.android.gms", "rejected_count": 0, "to": "2026-11-13T18:00:00Z"})]),
 ("100522", "operations-sms-refuses", "Envois de SMS refusés (garde SMS)", [ev("app.ops.app", {"background_count": 0, "count": 0, "from": "2026-11-16T13:00:00Z", "last_ts": "2026-11-16T13:16:20.276Z", "op": "send_sms", "package": TORCH[0], "rejected_count": 76, "to": "2026-11-16T14:00:00Z"})]),
 ("100521", "operations-appel-refuse", "Appel refusé (garde appels)", [ev("app.ops.app", {"background_count": 2, "count": 0, "from": "2026-11-16T13:00:00Z", "op": "call_phone", "package": "com.example.dialer.fraud", "rejected_count": 2, "to": "2026-11-16T14:00:00Z"})]),
 ("100160", "permission-envoi-sms", "Permission d'envoi de SMS accordée", [ev("app.permission_changed", {"package": TORCH[0], "permission": "android.permission.SEND_SMS", "granted": True}, 1)]),
 # --- v1.2 : gardes (security.policy, profile guard:<clé>, §11.1)
 ("100531", "garde-activee", "Garde SMS activée", [guard("guard_enabled", "sms", "sms")]),
 ("100532", "garde-desactivee", "Garde SMS désactivée (affaiblissement)", [guard("guard_disabled", "sms", "sms")]),
 ("100533", "garde-quarantaine", "Application mise en quarantaine", [guard("quarantined", "quarantine", TORCH[0])]),
 ("100534", "garde-liberee", "Application libérée de la quarantaine", [guard("released", "quarantine", TORCH[0])]),
 ("100530", "garde-permission-refusee", "Permission refusée par une garde : marqué", [guard("permission_denied", "sms", TORCH[0], "android.permission.SEND_SMS", 1)]),
 ("100535", "garde-permission-rendue", "Permission rendue par une garde", [guard("permission_restored", "sms", "com.example.otp", "android.permission.SEND_SMS")]),
 ("100187", "garde-echec", "Échec d'une garde sur un paquet (ok = false, alerte d'échec)", [guard("permission_denied", "sms", "com.example.app", "android.permission.SEND_SMS", 1, ok=False)]),
 # --- v1.2 : vue « pistage » (tracking.*, événements du collecteur)
 ("100540", "pistage-niveau-renforce", "Niveau de blocage renforcé (sév. 1)", [ev("tracking.level_changed", {"old": "equilibre", "new": "strict", "changes": 4, "user": "admin"}, 1, source="server")]),
 ("100541", "pistage-niveau-affaibli", "Niveau de blocage abaissé (sév. 2)", [ev("tracking.level_changed", {"old": "strict", "new": "permissif", "changes": 5, "user": "admin"}, 2, source="server")]),
 ("100546", "pistage-niveau-depuis-inconnu", "Niveau posé depuis un état inconnu (old absent, sév. 2)", [ev("tracking.level_changed", {"new": "equilibre", "changes": 2, "user": "admin"}, 2, source="server")]),
 ("100100", "pistage-niveau-imite", "tracking.* envoyé par un appareil : aucune alerte", [ev("tracking.level_changed", {"old": "strict", "new": "permissif", "user": "admin"}, 2)]),
 ("100542", "pistage-blocage", "Domaine bloqué depuis la console", [ev("tracking.override", {"domain": "graph.facebook.com", "action": "block", "forced": False, "user": "admin"}, 1, source="server")]),
 ("100543", "pistage-autorisation", "Domaine autorisé de force depuis la console", [ev("tracking.override", {"domain": "gate.cdn-update-check.example", "action": "allow", "forced": False, "user": "admin"}, 2, source="server")]),
 ("100544", "pistage-blocage-retire", "Blocage manuel retiré", [ev("tracking.override", {"domain": "graph.facebook.com", "action": "default", "forced": False, "previous": "block", "user": "admin"}, 2, source="server")]),
 ("100545", "pistage-blocage-indispensable", "Blocage forcé d'un domaine indispensable", [ev("tracking.override", {"domain": "fcm.googleapis.com", "action": "block", "forced": True, "user": "admin"}, 2, source="server")]),
 ("100542", "pistage-autorisation-retiree", "Autorisation retirée (retour au défaut, renforcement)", [ev("tracking.override", {"domain": "x.example", "action": "default", "forced": False, "previous": "allow", "user": "admin"}, 1, source="server")]),
]
for i, (rid, slug, desc, lines) in enumerate(cases, 1):
    with open(os.path.join(out, "%03d-%s.log" % (i, slug)), "w") as f:
        f.write("# %s\n# attendu: %s\n" % (desc, rid))
        for l in lines:
            f.write(l.replace('"private_dns_host":null,', '') + "\n")
print(len(cases), "cas")
