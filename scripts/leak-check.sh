#!/usr/bin/env bash
# Relavia leak check — field tool for real-network environments.
#
# Purpose (Step 11 acceptance, field half): the sandbox/CI leak
# rig proves DNS separation, global-mode behaviour and the IPv6
# switch against loopback fakes. The checks that need a REAL
# egress — public DNS resolver identity, WebRTC in a real
# browser, public IPv6 — live here, to be run by a human on a
# machine with the Relavia client connected to a real node.
#
# Usage:
#   RELAVIA_PROXY=127.0.0.1:2080 ./scripts/leak-check.sh
#     RELAVIA_PROXY  the client's local mixed inbound
#                    (default 127.0.0.1:2080)
#     MODE           "proxy" (default) or "tun"; in tun mode the
#                    system traffic is already captured, so the
#                    DNS section runs without the proxy flag.
#
# Exit code is 0 when every automated check passes; the WebRTC
# section is guidance-only by design (a script cannot inspect a
# browser's RTCPeerConnection candidates) and never fails the
# run — it prints exactly what to verify by hand.
set -u

PROXY="${RELVIA_PROXY:-127.0.0.1:2080}"
MODE="${MODE:-proxy}"
FAIL=0

say()  { printf '%s\n' "$*"; }
pass() { say "PASS: $*"; }
bad()  { say "FAIL: $*"; FAIL=1; }
info() { say "INFO: $*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || { say "missing tool: $1 (install it and re-run)"; exit 2; }
}
need curl
need dig

CURL_PROXY=()
if [ "$MODE" = "proxy" ]; then
  CURL_PROXY=(--proxy "http://$PROXY")
fi

say "== 1. Egress IP: direct vs via client =="
DIRECT_IP="$(curl -s --max-time 15 https://api.ipify.org || true)"
VIA_IP="$(curl -s --max-time 15 "${CURL_PROXY[@]}" https://api.ipify.org || true)"
info "direct egress: ${DIRECT_IP:-<none>}"
info "client egress: ${VIA_IP:-<none>}"
if [ -z "$VIA_IP" ]; then
  bad "no egress through the client (is it connected?)"
elif [ -n "$DIRECT_IP" ] && [ "$DIRECT_IP" = "$VIA_IP" ]; then
  bad "client egress equals direct egress — traffic is NOT going through the node"
else
  pass "client egress differs from direct egress"
fi

say "== 2. DNS resolver identity (who answers your queries) =="
# whoami.akamai.net returns the resolver's egress address.
if [ "$MODE" = "tun" ]; then
  RESOLVER_IP="$(dig +short whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null | tail -1)"
  if [ -n "$RESOLVER_IP" ]; then
    info "resolver egress (system path, TUN-captured): $RESOLVER_IP"
    if [ "$RESOLVER_IP" = "$VIA_IP" ]; then
      pass "DNS resolves on the tunnel side"
    else
      info "resolver egress != tunnel egress — expected when the node resolves remotely at ITS egress; FAIL only if this equals your ISP resolver"
    fi
  else
    info "akamai whoami did not answer; verify manually with any DNS leak test site"
  fi
else
  info "system-proxy mode does not capture raw DNS queries from other apps; the client's own resolution policy is covered by the automated rig (core/singbox, Step 11 cases). Skipping."
fi

say "== 3. IPv6 through the client =="
V6_VIA="$(curl -6 -s --max-time 15 "${CURL_PROXY[@]}" https://api6.ipify.org || true)"
V6_DIRECT="$(curl -6 -s --max-time 15 https://api6.ipify.org || true)"
info "direct IPv6: ${V6_DIRECT:-<none>}"
info "client IPv6: ${V6_VIA:-<none>}"
if [ -n "$V6_DIRECT" ] && [ -z "$V6_VIA" ]; then
  info "host has native IPv6 but none leaves via the client — consistent with ipv6=off, ipv6=tunnel with a v4-only node, or a v4-only tunnel. In TUN mode confirm this matches the configured policy."
fi

say "== 4. Direct-list sanity (rule mode) =="
info "fetch a name you route DIRECT and confirm its egress equals the direct egress above; fetch any other name and confirm it equals the client egress. Automate by exporting CHECK_DIRECT_HOST / CHECK_PROXY_HOST."
if [ -n "${CHECK_DIRECT_HOST:-}" ]; then
  D_IP="$(curl -s --max-time 15 "${CURL_PROXY[@]}" "https://${CHECK_DIRECT_HOST}/" -o /dev/null -w '%{remote_ip}' || true)"
  info "direct-listed host resolved/contacted at: ${D_IP:-<failed>}"
fi
if [ -n "${CHECK_PROXY_HOST:-}" ]; then
  P_IP="$(curl -s --max-time 15 "${CURL_PROXY[@]}" "https://${CHECK_PROXY_HOST}/" -o /dev/null -w '%{remote_ip}' || true)"
  info "proxied host resolved/contacted at: ${P_IP:-<failed>}"
fi

say "== 5. WebRTC (manual, guidance only) =="
cat <<'EOF'
A script cannot inspect a browser's WebRTC candidates. Do this
by hand, once per browser and mode:
  1. Connect the client. Open any WebRTC leak test page
     (search "webrtc leak test"; the community test pages all
     enumerate RTCPeerConnection candidates).
  2. The page must show NO public IP other than the client's
     egress IP printed in section 1. A second, different
     public IP = WebRTC is bypassing the client.
  3. System-proxy mode is EXPECTED to fail this check until
     the browser is configured — see
     core/routecfg/defaults/README.md (Firefox:
     media.peerconnection.enabled=false; Chrome/Edge:
     WebRtcIPHandlingPolicy=disable_non_proxied_udp).
EOF

if [ "$FAIL" -eq 0 ]; then
  say "== RESULT: automated checks passed (WebRTC section is manual) =="
else
  say "== RESULT: FAILURES above =="
fi
exit "$FAIL"
