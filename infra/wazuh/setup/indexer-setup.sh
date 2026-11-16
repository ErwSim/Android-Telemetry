#!/usr/bin/env bash
# Configures the Wazuh indexer for Watchpost (called by install.sh, safe to rerun):
#  - "watchpost" index template (order 1, complements Filebeat's "wazuh" template):
#      * 1 shard, 0 replicas (single node);
#      * data.watchpost.data.location as geo_point (map);
#      * fields of data.watchpost.data.* as keyword by default: the event types share this
#        namespace and the same field name can hold a number, a boolean or a text depending on
#        the type; without this, the first type seen sets the mapping and the next ones are
#        REJECTED by the indexer (events lost in wazuh-archives-*). The known numeric fields are
#        typed explicitly (with ignore_malformed) for the charts.
#  - ISM retention policies (WAZUH_ALERTS_RETENTION_DAYS, WAZUH_ARCHIVES_RETENTION_DAYS).
# Authentication with the admin certificate inside the container (no password in clear).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib/common.sh
source "$INFRA_DIR/lib/common.sh"

ALERTS_DAYS="$(env_get WAZUH_ALERTS_RETENTION_DAYS)"; ALERTS_DAYS="${ALERTS_DAYS:-180}"
ARCHIVES_DAYS="$(env_get WAZUH_ARCHIVES_RETENTION_DAYS)"; ARCHIVES_DAYS="${ARCHIVES_DAYS:-90}"
[[ "$ALERTS_DAYS" =~ ^[0-9]+$ && "$ARCHIVES_DAYS" =~ ^[0-9]+$ ]] || die "invalid retention periods"

es() { es_admin "$@"; }

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

# Leaves of data.watchpost.data.* and data.watchpost_watch.* as keyword, whatever their JSON type. The
# objects (security.log "fields", heartbeat "collectors"…) stay objects: a "match_mapping_type: *"
# template would capture them too and get the document rejected (observed).
DYN="$(
  sep=""
  for path in data.watchpost.data data.watchpost_watch; do
    for t in string long double boolean; do
      printf '%s{ "%s_%s_kw": { "path_match": "%s.*", "match_mapping_type": "%s", "mapping": { "type": "keyword", "ignore_above": 1024 } } }' \
        "$sep" "${path//./_}" "$t" "$path" "$t"
      sep=","
    done
  done
)"

info "watchpost index template (geo_point, keyword by default, 1 shard)"
es PUT /_template/watchpost body <<EOF | grep -q '"acknowledged":true' || die "watchpost index template failed"
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
          "watchpost": {
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

# policy <id> <days> <pattern1,pattern2> <description>
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
      info "Policy $id unchanged (${days} d)"
    else
      q="?if_seq_no=$seq&if_primary_term=$term"
      es PUT "/_plugins/_ism/policies/$id$q" body <<<"$body" | grep -q '"_id"' || die "update of $id failed"
      info "Policy $id updated (${days} d)"
    fi
  else
    es PUT "/_plugins/_ism/policies/$id" body <<<"$body" | grep -q '"_id"' || die "creation of $id failed"
    info "Policy $id created (${days} d)"
  fi
  # Already existing indices: attach (those without a policy), then switch to the latest version.
  local p
  for p in ${patterns//,/ }; do
    p="${p//\"/}"
    es POST "/_plugins/_ism/add/$p" body <<<"{\"policy_id\":\"$id\"}" >/dev/null || true
    es POST "/_plugins/_ism/change_policy/$p" body <<<"{\"policy_id\":\"$id\"}" >/dev/null || true
  done
}

policy watchpost-alerts-retention "$ALERTS_DAYS" "wazuh-alerts-*" "Watchpost: deletion of the Wazuh alerts after $ALERTS_DAYS days"
policy watchpost-archives-retention "$ARCHIVES_DAYS" "wazuh-archives-*" "Watchpost: deletion of the archives (all events) after $ARCHIVES_DAYS days"
policy watchpost-monitoring-retention 30 "wazuh-monitoring-*,wazuh-statistics-*" "Watchpost: deletion of the Wazuh monitoring indices after 30 days"
