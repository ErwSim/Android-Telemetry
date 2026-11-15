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
printf '%s\n' "# Généré par vigie-init.sh à chaque démarrage." "logcollector.queue_size=65536" \
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

echo "vigie-init : configuration Vigie appliquée"
