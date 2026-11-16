#!/usr/bin/env bash
# Replays every test case of the Watchpost rules with wazuh-logtest and checks the identifier of the
# rule fired by the last line of each case.
#   ./wazuh/tests/run-tests.sh            (from infra/, on the host: goes through docker compose)
#   ./wazuh/tests/run-tests.sh 015 100181 (filter: substring of the file name or expected rule)
# Exit code: number of failed cases (0 = all pass).
set -Euo pipefail

if [[ ! -x /var/ossec/bin/wazuh-logtest ]]; then
  INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  # shellcheck source=../../lib/common.sh
  source "$INFRA_DIR/lib/common.sh"
  exec docker compose --project-directory "$INFRA_DIR" -f "$INFRA_DIR/docker-compose.yml" \
    ${WATCHPOST_COMPOSE_EXTRA:+-f "$WATCHPOST_COMPOSE_EXTRA"} \
    exec -T wazuh.manager bash /watchpost/tests/run-tests.sh "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNS_HOST="$(head -n1 /var/ossec/etc/lists/watchpost-private-dns-hosts 2>/dev/null | cut -d: -f1)"
DNS_HOST="${DNS_HOST:-dns.invalid}"
pass=0 fail=0 failed=()
for f in "$DIR"/cases/*.log; do
  name="$(basename "$f" .log)"
  if (($#)); then
    match=0
    for p in "$@"; do [[ "$name" == *"$p"* || "$(grep -m1 '^# expected:' "$f")" == *"$p"* ]] && match=1; done
    ((match)) || continue
  fi
  expected="$(sed -n 's/^# expected: *//p' "$f" | head -n1)"
  nlines="$(grep -vc '^#' "$f")"
  out="$(grep -v '^#' "$f" | sed "s/@@DNS_HOST@@/$DNS_HOST/g" | timeout 60 /var/ossec/bin/wazuh-logtest 2>&1)"
  phases="$(grep -c '^\*\*Phase 1' <<<"$out" || true)"
  got="$(grep -oE "^\s+id: '[0-9]+'" <<<"$out" | tail -n1 | grep -oE '[0-9]+' || true)"
  level="$(grep -oE "^\s+level: '[0-9]+'" <<<"$out" | tail -n1 | grep -oE '[0-9]+' || true)"
  if [[ "$phases" == "$nlines" && "$got" == "$expected" ]]; then
    ((pass++))
    printf 'OK     %-45s rule %-6s level %s\n' "$name" "$got" "$level"
  else
    ((fail++))
    failed+=("$name")
    printf 'FAIL   %-45s expected %s, got %s (%s/%s lines analysed)\n' "$name" "$expected" "${got:-none}" "$phases" "$nlines"
  fi
done
echo "----"
echo "$pass passed, $fail failed"
((fail)) && printf '  %s\n' "${failed[@]}"
exit "$fail"
