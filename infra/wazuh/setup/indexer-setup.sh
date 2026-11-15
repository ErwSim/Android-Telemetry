#!/usr/bin/env bash
# Configure l'indexeur Wazuh pour Vigie (appelé par install.sh, rejouable) :
#  - modèle d'index « vigie » (ordre 1, complète le modèle « wazuh » de Filebeat) :
#      * 1 shard, 0 réplique (nœud unique) ;
#      * data.vigie.data.location en geo_point (carte) ;
#      * champs de data.vigie.data.* en keyword par défaut : les types d'événements partagent cet
#        espace de noms et un même nom de champ peut y porter un nombre, un booléen ou un texte
#        selon le type ; sans cela, le premier type vu fixe le mapping et les suivants sont REJETÉS
#        par l'indexeur (événements perdus dans wazuh-archives-*). Les champs numériques connus sont
#        typés explicitement (avec ignore_malformed) pour les graphiques.
#  - politiques ISM de rétention (WAZUH_ALERTS_RETENTION_DAYS, WAZUH_ARCHIVES_RETENTION_DAYS).
# Authentification par le certificat admin dans le conteneur (aucun mot de passe en clair).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib/common.sh
source "$INFRA_DIR/lib/common.sh"

ALERTS_DAYS="$(env_get WAZUH_ALERTS_RETENTION_DAYS)"; ALERTS_DAYS="${ALERTS_DAYS:-180}"
ARCHIVES_DAYS="$(env_get WAZUH_ARCHIVES_RETENTION_DAYS)"; ARCHIVES_DAYS="${ARCHIVES_DAYS:-90}"
[[ "$ALERTS_DAYS" =~ ^[0-9]+$ && "$ARCHIVES_DAYS" =~ ^[0-9]+$ ]] || die "durées de rétention invalides"

# es <méthode> <chemin> [corps JSON sur l'entrée standard]
es() {
  dc exec -T wazuh.indexer curl -sS --cacert config/certs/root-ca.pem \
    --cert config/certs/admin.pem --key config/certs/admin-key.pem \
    -X "$1" -H 'Content-Type: application/json' "https://localhost:9200$2" ${3:+--data-binary @-}
}

num() { printf '"%s":{"type":"%s","ignore_malformed":true}' "$1" "$2"; }
NUMERIC="$(
  IFS=,
  f=()
  for n in lat lon acc_m alt_m speed_mps bearing_deg battery_pct pct temperature_c rssi freq_mhz \
    signal_dbm patch_age_days failed_attempts sightings queue_depth address_count port; do
    f+=("$(num "$n" float)")
  done
  for n in uptime_ms queue_bytes dropped_total dropped delta_ms free_bytes total_bytes rx_bytes tx_bytes \
    total_storage_bytes total_ram_bytes sdk_int version_code target_sdk uid; do
    f+=("$(num "$n" long)")
  done
  echo "${f[*]}"
)"

# Feuilles de data.vigie.data.* et data.vigie_watch.* en keyword, quel que soit leur type JSON. Les
# objets (security.log « fields », heartbeat « collectors »…) restent des objets : un modèle
# « match_mapping_type: * » les capturerait aussi et ferait rejeter le document (constaté).
DYN="$(
  sep=""
  for path in data.vigie.data data.vigie_watch; do
    for t in string long double boolean; do
      printf '%s{ "%s_%s_kw": { "path_match": "%s.*", "match_mapping_type": "%s", "mapping": { "type": "keyword", "ignore_above": 1024 } } }' \
        "$sep" "${path//./_}" "$t" "$path" "$t"
      sep=","
    done
  done
)"

info "Modèle d'index vigie (geo_point, keyword par défaut, 1 shard)"
es PUT /_template/vigie body <<EOF | grep -q '"acknowledged":true' || die "échec du modèle d'index vigie"
{
  "order": 1,
  "index_patterns": ["wazuh-alerts-4.x-*", "wazuh-archives-4.x-*"],
  "settings": {
    "index.number_of_shards": 1,
    "index.number_of_replicas": 0,
    "index.auto_expand_replicas": "false",
    "index.refresh_interval": "5s"
  },
  "mappings": {
    "dynamic_templates": [
      $DYN
    ],
    "properties": {
      "data": {
        "properties": {
          "vigie": {
            "properties": {
              "seq": { "type": "long" },
              "sev": { "type": "integer" },
              "ts": { "type": "date", "ignore_malformed": true },
              "received_at": { "type": "date", "ignore_malformed": true },
              "data": {
                "properties": {
                  "location": { "type": "geo_point", "ignore_malformed": true },
                  $NUMERIC
                }
              }
            }
          },
          "Elapsed": { "type": "long", "ignore_malformed": true },
          "T": { "type": "date", "ignore_malformed": true }
        }
      }
    }
  }
}
EOF

# policy <id> <jours> <motif1,motif2> <description>
policy() {
  local id="$1" days="$2" patterns="$3" desc="$4" body cur seq term q=""
  patterns="\"${patterns//,/\",\"}\""
  body="$(
    cat <<EOF
{ "policy": {
  "description": "$desc",
  "default_state": "hot",
  "states": [
    { "name": "hot", "actions": [],
      "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "${days}d" } } ] },
    { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
  ],
  "ism_template": [ { "index_patterns": [ $patterns ], "priority": 100 } ]
} }
EOF
  )"
  cur="$(es GET "/_plugins/_ism/policies/$id" || true)"
  if [[ "$cur" == *'"_seq_no"'* ]]; then
    seq="$(grep -oE '"_seq_no":[0-9]+' <<<"$cur" | cut -d: -f2)"
    term="$(grep -oE '"_primary_term":[0-9]+' <<<"$cur" | cut -d: -f2)"
    if grep -q "\"min_index_age\":\"${days}d\"" <<<"${cur// /}"; then
      info "Politique $id inchangée (${days} j)"
    else
      q="?if_seq_no=$seq&if_primary_term=$term"
      es PUT "/_plugins/_ism/policies/$id$q" body <<<"$body" | grep -q '"_id"' || die "échec de la mise à jour de $id"
      info "Politique $id mise à jour (${days} j)"
    fi
  else
    es PUT "/_plugins/_ism/policies/$id" body <<<"$body" | grep -q '"_id"' || die "échec de la création de $id"
    info "Politique $id créée (${days} j)"
  fi
  # Index déjà existants : rattachement (sans politique) puis passage à la dernière version.
  local p
  for p in ${patterns//,/ }; do
    p="${p//\"/}"
    es POST "/_plugins/_ism/add/$p" body <<<"{\"policy_id\":\"$id\"}" >/dev/null || true
    es POST "/_plugins/_ism/change_policy/$p" body <<<"{\"policy_id\":\"$id\"}" >/dev/null || true
  done
}

policy vigie-alerts-retention "$ALERTS_DAYS" "wazuh-alerts-*" "Vigie : suppression des alertes Wazuh après $ALERTS_DAYS jours"
policy vigie-archives-retention "$ARCHIVES_DAYS" "wazuh-archives-*" "Vigie : suppression des archives (tous les événements) après $ARCHIVES_DAYS jours"
policy vigie-monitoring-retention 30 "wazuh-monitoring-*,wazuh-statistics-*" "Vigie : suppression des index de supervision Wazuh après 30 jours"
