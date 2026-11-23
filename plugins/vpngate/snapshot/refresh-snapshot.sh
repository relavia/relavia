#!/bin/sh
# Refresh the bundled VPN Gate list snapshot from the official
# endpoints (book 7.3 source; the CSV is public data the project
# is authorized to redistribute for client use).
#
# The snapshot is the pool's bootstrap fallback: when a fresh
# install in a restricted network cannot reach any endpoint and
# has no cache yet, the app serves this list — labelled with its
# capture date, never as live data (see ../snapshot.go).
#
# Run this before each release (release checklist, docs/step15),
# then run the plugin tests: BundledSnapshot is fully validated
# (CSV shape + real parse) by `go test ./...` in plugins/vpngate.
set -eu
cd "$(dirname "$0")"

UA="Relavia-VPNGate-Plugin/1.0 (+https://www.vpngate.net/en/)"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Official endpoints in the manifest's order: HTTPS first, the
# official HTTP API endpoint as the fallback.
if ! curl -fsS --max-time 120 -A "$UA" -o "$tmp" https://www.vpngate.net/api/iphone/; then
    echo "HTTPS endpoint failed, trying the official HTTP endpoint" >&2
    curl -fsS --max-time 120 -A "$UA" -o "$tmp" http://www.vpngate.net/api/iphone/
fi

# Shape markers of the official CSV (the full anti-poisoning
# validation runs in Go at load time and in the plugin tests).
grep -q '\*vpn_servers' "$tmp"
grep -q 'OpenVPN_ConfigData_Base64' "$tmp"

cp "$tmp" vpngate-list.csv
captured="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{\n  "capturedAt": "%s",\n  "source": "https://www.vpngate.net/api/iphone/"\n}\n' "$captured" > meta.json
echo "snapshot refreshed: $(wc -c < vpngate-list.csv) bytes, captured $captured"
echo "now validate: (cd .. && go test ./...)"
