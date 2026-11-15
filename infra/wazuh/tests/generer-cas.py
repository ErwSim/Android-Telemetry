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
def ev(typ, data, sev=0, dev="dev_7k2m9q", name="s25"):
    seq[0] += 1
    return json.dumps({"vigie": {"device_id": dev, "device_name": name, "id": "01JTEST%019d" % seq[0],
        "ts": "2026-11-15T21:43:03.974Z", "received_at": "2026-11-15T21:43:05.120Z", "seq": seq[0],
        "type": typ, "domain": typ.split('.')[0], "sev": sev, "data": data}}, ensure_ascii=False, separators=(',', ':'))
def agh(qh, filtered=False, listid=10, ip="203.0.113.7", cp="dot"):
    d = {"T": "2026-11-15T22:30:36.905394867Z", "QH": qh, "QT": "A", "QC": "IN", "CP": cp,
         "Answer": "PjuBgAABAAEAAAAAD2FwcC1tZWFzdXJlbWVudANjb20AAAEAAcAMAAEAAQAAAAoABAAAAAA=", "IP": ip}
    if filtered:
        d["Result"] = {"Rules": [{"Text": "||%s^" % qh, "FilterListID": listid}], "Reason": 3, "IsFiltered": True}
    else:
        d["Result"] = {}; d["Upstream"] = "https://dns.quad9.net:443/dns-query"
    d["Elapsed"] = 186617
    return json.dumps(d, separators=(',', ':'))
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
 ("100170", "micro-utilise", "Micro utilisé", [ev("sensor.microphone", {"recording": True, "source": "mic", "package": "com.whatsapp", "silenced": False})]),
 ("100171", "camera-utilisee", "Caméra utilisée", [ev("sensor.camera", {"camera_id": "1", "in_use": True, "package": "com.whatsapp"})]),
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
 ("100210", "journal-securite-ordinaire", "Journal de sécurité ordinaire", [slog("app_process_start", {"process": "com.android.chrome", "uid": 10100})]),
 ("100211", "journal-adb-shell", "Shell ADB interactif", [slog("adb_shell_interactive")]),
 ("100212", "journal-adb-commande", "Commande ADB", [slog("adb_shell_cmd", {"command": "pm list packages"})]),
 ("100213", "journal-adb-fichier", "Transfert de fichier ADB", [slog("sync_recv_file", {"path": "/sdcard/DCIM/x.jpg"})]),
 ("100214", "journal-keyguard-echec", "Échec d'authentification (journal)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "method": "pin"})]),
 ("100215", "journal-keyguard-repetes", "5 échecs (journal)", [slog("keyguard_dismiss_auth_attempt", {"success": False, "method": "pin"}) for _ in range(5)]),
 ("100216", "journal-ac-installee", "AC installée (journal)", [slog("cert_authority_installed", {"subject": "CN=x", "result": 1})]),
 ("100217", "journal-arrete", "Journalisation arrêtée", [slog("logging_stopped")]),
 ("100218", "journal-tampon-critique", "Tampon du journal presque plein", [slog("log_buffer_size_critical")]),
 ("100219", "journal-violation-cle", "Violation d'intégrité de clé", [slog("key_integrity_violation", {"alias": "x", "uid": 1000})]),
 ("100220", "journal-autotest-crypto", "Échec de l'autotest crypto", [slog("crypto_self_test_completed", {"success": 0})]),
 ("100221", "journal-effacement-echec", "Échec d'effacement", [slog("wipe_failure")]),
 ("100222", "journal-restriction-retiree", "Restriction utilisateur retirée", [slog("user_restriction_removed", {"admin": "io.github.erwsim.vigie", "restriction": "no_debugging_features"})]),
 ("100223", "journal-support-monte", "Support amovible monté", [slog("media_mount", {"path": "/storage/ABCD-1234", "label": "USB"})]),
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
 ("100105", "severite-critique-type-inconnu", "Type inconnu, sévérité 3", [ev("device.unknown_future_type", {"x": 1}, 3)]),
 ("100106", "severite-avertissement-type-inconnu", "Type inconnu, sévérité 2", [ev("net.unknown_future_type", {"x": 1}, 2)]),
 ("100400", "adguard-requete", "Requête DNS non bloquée", [agh("example.org")]),
 ("100401", "adguard-bloquee", "Requête DNS bloquée", [agh("app-measurement.com", True, 1)]),
 ("100402", "adguard-menace", "Domaine du flux de menaces", [agh("malware.example", True, 30)]),
 ("100403", "adguard-rafale", "60 requêtes bloquées en rafale", [agh("ads%d.example" % i, True, 10) for i in range(60)]),
 ("100404", "adguard-menaces-repetees", "5 domaines malveillants", [agh("c2-%d.example" % i, True, 30) for i in range(5)]),
]
for i, (rid, slug, desc, lines) in enumerate(cases, 1):
    with open(os.path.join(out, "%03d-%s.log" % (i, slug)), "w") as f:
        f.write("# %s\n# attendu: %s\n" % (desc, rid))
        for l in lines:
            f.write(l.replace('"private_dns_host":null,', '') + "\n")
print(len(cases), "cas")
