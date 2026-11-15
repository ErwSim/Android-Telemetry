#!/usr/bin/env bash
# Rejoue tous les cas de test des règles Vigie avec wazuh-logtest et vérifie l'identifiant de la
# règle déclenchée par la dernière ligne de chaque cas.
#   ./wazuh/tests/run-tests.sh            (depuis infra/, sur l'hôte : passe par docker compose)
#   ./wazuh/tests/run-tests.sh 015 100181 (filtre : sous-chaîne du nom de fichier)
# Code de sortie : nombre de cas en échec (0 = tout passe).
set -Euo pipefail

if [[ ! -x /var/ossec/bin/wazuh-logtest ]]; then
  INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  # shellcheck source=../../lib/common.sh
  source "$INFRA_DIR/lib/common.sh"
  exec docker compose --project-directory "$INFRA_DIR" -f "$INFRA_DIR/docker-compose.yml" \
    ${VIGIE_COMPOSE_EXTRA:+-f "$VIGIE_COMPOSE_EXTRA"} \
    exec -T wazuh.manager bash /vigie/tests/run-tests.sh "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNS_HOST="$(head -n1 /var/ossec/etc/lists/vigie-private-dns-hosts 2>/dev/null | cut -d: -f1)"
DNS_HOST="${DNS_HOST:-dns.invalid}"
pass=0 fail=0 failed=()
for f in "$DIR"/cases/*.log; do
  name="$(basename "$f" .log)"
  if (($#)); then
    match=0
    for p in "$@"; do [[ "$name" == *"$p"* || "$(grep -m1 '^# attendu:' "$f")" == *"$p"* ]] && match=1; done
    ((match)) || continue
  fi
  expected="$(sed -n 's/^# attendu: *//p' "$f" | head -n1)"
  nlines="$(grep -vc '^#' "$f")"
  out="$(grep -v '^#' "$f" | sed "s/@@DNS_HOST@@/$DNS_HOST/g" | timeout 60 /var/ossec/bin/wazuh-logtest 2>&1)"
  phases="$(grep -c '^\*\*Phase 1' <<<"$out" || true)"
  got="$(grep -oE "^\s+id: '[0-9]+'" <<<"$out" | tail -n1 | grep -oE '[0-9]+' || true)"
  level="$(grep -oE "^\s+level: '[0-9]+'" <<<"$out" | tail -n1 | grep -oE '[0-9]+' || true)"
  if [[ "$phases" == "$nlines" && "$got" == "$expected" ]]; then
    ((pass++))
    printf 'OK     %-45s règle %-6s niveau %s\n' "$name" "$got" "$level"
  else
    ((fail++))
    failed+=("$name")
    printf 'ÉCHEC  %-45s attendu %s, obtenu %s (%s/%s lignes analysées)\n' "$name" "$expected" "${got:-aucune}" "$phases" "$nlines"
  fi
done
echo "----"
echo "$pass réussi(s), $fail échec(s)"
((fail)) && printf '  %s\n' "${failed[@]}"
exit "$fail"
