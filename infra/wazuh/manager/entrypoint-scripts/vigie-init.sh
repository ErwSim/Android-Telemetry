#!/usr/bin/env bash
# Exécuté par l'image wazuh-manager à chaque démarrage (/entrypoint-scripts/*.sh), après la
# configuration de Filebeat et avant le lancement des démons Wazuh et de Filebeat.
set -euo pipefail

FB=/etc/filebeat/filebeat.yml


# 1. Archives : indexer TOUS les événements (archives.json -> wazuh-archives-4.x-*).
#    Le fichier est réécrit depuis l'image à chaque démarrage, on le modifie donc à chaque fois.
sed -i '/^    archives:/{n;s/enabled: false/enabled: true/}' "$FB"

# 2. Filebeat : retire le champ « Answer »/« OrigAnswer » du journal AdGuard (réponse DNS
#    empaquetée en base64, volumineuse et inexploitable) avant l'envoi à l'indexeur. Le décodage
#    JSON se fait dans le pipeline d'ingestion de l'indexeur : on agit donc sur le texte brut,
#    y compris sur sa copie échappée dans full_log.
if ! grep -q vigie_strip_dns_answer "$FB"; then
  cat >>"$FB" <<'EOF'

processors:
  - script:
      lang: javascript
      id: vigie_strip_dns_answer
      source: >
        function process(event) {
          var m = event.Get("message");
          if (typeof m === "string" && m.indexOf('Answer') !== -1) {
            event.Put("message", m.replace(/,\\?"(Orig)?Answer\\?":\\?"[A-Za-z0-9+\/=]*\\?"/g, ""));
          }
        }
EOF
fi

# 2b. Débit : la file entre wazuh-logcollector et l'analyse (1024 lignes par défaut) déborde quand
#     le collecteur exporte d'un coup le tampon d'un téléphone resté hors ligne (« Target 'agent'
#     message queue is full… Log lines may be lost », constaté à l'essai avec 3 h d'historique).
# 2c. Corrélation : avec plusieurs fils d'analyse (défaut : un par processeur), des événements reçus
#     dans la même milliseconde sont évalués en parallèle et ne se voient pas entre eux ; les règles
#     de corrélation (100489 : détections du collecteur, écrites par rafales ; 100502 : app.risk
#     après app.installed) les manquaient (constaté à l'essai v1.2). Un seul fil : ordre du fichier
#     respecté ; largement suffisant pour quelques téléphones (débit mesuré dans infra/README.md §11.2).
printf '%s\n' "# Généré par vigie-init.sh à chaque démarrage." "logcollector.queue_size=65536" \
  "analysisd.event_threads=1" "analysisd.rule_matching_threads=1" \
  >/var/ossec/etc/local_internal_options.conf
chown root:wazuh /var/ossec/etc/local_internal_options.conf
chmod 640 /var/ossec/etc/local_internal_options.conf

# 3. Liste CDB des hôtes DNS privés attendus (règle 100195).
LIST=/var/ossec/etc/lists/vigie-private-dns-hosts
: >"$LIST"
for h in ${VIGIE_PRIVATE_DNS_HOSTS:-}; do
  printf '%s:\n' "$h" >>"$LIST"
done
[[ -s "$LIST" ]] || printf 'dns.invalid:\n' >>"$LIST"
chown wazuh:wazuh "$LIST"
chmod 660 "$LIST"

# 4. Mot de passe d'enrôlement d'agents aléatoire (aucun agent Wazuh n'est prévu).
if [[ ! -s /var/ossec/etc/authd.pass ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >/var/ossec/etc/authd.pass
  chown root:wazuh /var/ossec/etc/authd.pass
  chmod 640 /var/ossec/etc/authd.pass
fi

# 5. Règles Vigie : propriétaire attendu par wazuh-analysisd.
chown wazuh:wazuh /var/ossec/etc/rules/vigie_*.xml 2>/dev/null || true
chmod 660 /var/ossec/etc/rules/vigie_*.xml 2>/dev/null || true

# 6. Rétention des archives brutes sur disque (archives.json.gz quotidiens, jamais purgés par
#    Wazuh) : les données restent dans l'indexeur, soumises à la politique ISM.
find /var/ossec/logs/archives -type f -name '*.gz' -mtime +"${VIGIE_ARCHIVES_FILE_DAYS:-14}" -delete 2>/dev/null || true
find /var/ossec/logs/alerts -type f -name '*.gz' -mtime +"${VIGIE_ARCHIVES_FILE_DAYS:-14}" -delete 2>/dev/null || true

# 7. Notifications optionnelles (webhook compatible ntfy, e-mail SMTP) : intégration Wazuh
#    « custom-vigie-notify » pour les alertes de niveau >= VIGIE_NOTIFY_LEVEL et pour le silence de
#    l'agent (100301) et la remise à zéro de séquence (100305). ossec.conf est recopié à chaque
#    démarrage : sans configuration, aucune intégration n'existe.
NOTIFY_CONF=/var/ossec/etc/vigie-notify.json
if [[ -n "${VIGIE_NOTIFY_URL:-}${VIGIE_NOTIFY_SMTP_HOST:-}" ]]; then
  LEVEL="${VIGIE_NOTIFY_LEVEL:-10}"
  [[ "$LEVEL" =~ ^[0-9]+$ ]] || LEVEL=10
  install -o root -g wazuh -m 750 /vigie/notify/custom-vigie-notify /vigie/notify/custom-vigie-notify.py \
    /var/ossec/integrations/
  /var/ossec/framework/python/bin/python3 - "$NOTIFY_CONF" <<'PY'
import json, os, sys
e = os.environ.get
conf = {"url": e("VIGIE_NOTIFY_URL", ""), "topic": e("VIGIE_NOTIFY_TOPIC", ""), "token": e("VIGIE_NOTIFY_TOKEN", ""),
        "smtp_host": e("VIGIE_NOTIFY_SMTP_HOST", ""), "smtp_port": e("VIGIE_NOTIFY_SMTP_PORT", "587"),
        "smtp_tls": e("VIGIE_NOTIFY_SMTP_TLS", "starttls"), "smtp_user": e("VIGIE_NOTIFY_SMTP_USER", ""),
        "smtp_password": e("VIGIE_NOTIFY_SMTP_PASSWORD", ""), "smtp_from": e("VIGIE_NOTIFY_SMTP_FROM", ""),
        "smtp_to": e("VIGIE_NOTIFY_SMTP_TO", "")}
with open(sys.argv[1], "w") as f:
    json.dump(conf, f)
PY
  chown root:wazuh "$NOTIFY_CONF"
  chmod 640 "$NOTIFY_CONF"
  # Règles de surveillance sous le seuil choisi (silence : 7, séquence remise à zéro : 8).
  EXTRA=""
  ((LEVEL > 7)) && EXTRA="100301"
  ((LEVEL > 8)) && EXTRA="$EXTRA,100305"
  {
    echo "<ossec_config>"
    printf '  <integration>\n    <name>custom-vigie-notify</name>\n    <level>%s</level>\n    <alert_format>json</alert_format>\n  </integration>\n' "$LEVEL"
    if [[ -n "$EXTRA" ]]; then
      printf '  <integration>\n    <name>custom-vigie-notify</name>\n    <rule_id>%s</rule_id>\n    <alert_format>json</alert_format>\n  </integration>\n' "${EXTRA#,}"
    fi
    echo "</ossec_config>"
  } >>/var/ossec/etc/ossec.conf
  echo "vigie-init : notifications actives (niveau >= $LEVEL${EXTRA:+, règles $EXTRA})"
else
  rm -f "$NOTIFY_CONF"
fi

echo "vigie-init : configuration Vigie appliquée"
