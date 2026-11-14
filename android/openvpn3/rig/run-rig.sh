#!/usr/bin/env bash
# Loopback handshake rig for the production OpenVPN 3 core
# (docs/真机连接失败诊断-2026-11-14.md §8, docs/openvpn3构建尖峰.md).
#
# What this proves, on a clean machine, end to end:
#
#   1. The production SWIG core — the same pinned openvpn3
#      source and the same build glue (android/openvpn3/
#      CMakeLists.txt) that produce the APK's
#      libovpn3android.so, in its host variant — completes a
#      full session against a real SoftEther VPN Server with
#      its OpenVPN clone enabled, configured the VPN Gate way
#      (TCP, shared self-signed client certificate mapped to
#      a hub user by CN, SecureNAT): TLS handshake, Peer Info
#      sent, PUSH_REPLY processed, CONNECTED, data channel
#      AES-128-CBC/SHA1. The profile text is produced by the
#      production Go path (parsers -> specnode ->
#      openvpn.RenderProfile) from a VPN Gate-shaped document.
#   2. The same core completes against a genuine OpenVPN
#      2.6.x server (control group A).
#   3. The core's first control packet is byte-identical to
#      desktop OpenVPN 2.x's (control group B + byte_relay.py
#      capture; tcpdump is not available in every sandbox,
#      the relay sees the same wire bytes).
#   4. The Peer Info the core sends advertises the CBC
#      ciphers (IV_CIPHERS, production parity with
#      Ovpn3Client.runSession's enableNonPreferredDCAlgorithms).
#      A bisect run with the pre-fix AEAD-only advertisement
#      is recorded (RIG_BISECT_AEAD_ONLY) but not gated: on a
#      tolerant server it passes too; on a server vintage
#      that reproduces the real-device stall it is the
#      informative difference.
#   5. The production-rendered pool profile carries the pool
#      TLS ceiling (tls-version-max 1.2, core/openvpn
#      genconfig.go, diagnosis §10), and the core under test
#      is the pinned tree PLUS the downstream patches in
#      android/openvpn3/patches/ (0001 makes the core honor
#      that directive): the main run must therefore negotiate
#      TLS 1.2 and pass, and a record run with the ceiling
#      stripped must still pass at TLS 1.3 (the patch did not
#      break the modern path).
#   6. Legacy reproduction (diagnosis §10): against SoftEther
#      4.29 — whose OpenVPN clone has no client-certificate
#      capture at all — the same production profile must fail
#      with the exact real-device signature (Session ACTIVE,
#      then AUTH_FAILED; server security log: "External
#      server authentication", empty user name). This gate
#      pins a KNOWN server-side defect: if it ever flips, the
#      §10 conclusion and the pool TLS ceiling rationale must
#      be revisited, not silently celebrated.
#
# Assertion endpoint: control-channel completion (CONNECTED
# event + negotiated cipher cross-checked in both logs).
# Payload traffic through a real TUN device is out of scope,
# as in the desktop process-adapter rig; the driver's
# stand-in TUN (a Unix-domain socket pair) exists only to let
# the core finish TUN setup. A loopback pass is NOT a public
# -network L5 pass — see the diagnosis document.
#
# Requirements (CI installs them): go, JDK 17 (javac + JAVA_HOME
# or javac on PATH), swig 4.x, cmake, git, openssl, openvpn
# 2.6.x, python3, curl, and the native dev packages the host
# core build links (libasio-dev libfmt-dev libjsoncpp-dev
# liblz4-dev libxxhash-dev libssl-dev).
#
# Everything runs under $RIG_WORK (default: a mktemp dir);
# logs are copied to ./rig-out/ at the end for CI artifacts.

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
RIG_DIR="$REPO_ROOT/android/openvpn3/rig"
WORK=${RIG_WORK:-$(mktemp -d /tmp/relavia-rig.XXXXXX)}
OUT="$REPO_ROOT/rig-out"
mkdir -p "$WORK" "$OUT"

# SoftEther pin (the real VPN Gate counterparty family).
SOFTETHER_TAG=v4.44-9807-rtm
SOFTETHER_TARBALL=softether-vpnserver-v4.44-9807-rtm-2025.04.16-linux-x64-64bit.tar.gz
SOFTETHER_URL=https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/$SOFTETHER_TAG/$SOFTETHER_TARBALL
SOFTETHER_SHA256=e423e7f94a9f1f97a77b6dd425ba54505f69978964ff97843c90cc619fb70599

# openvpn3 pin: single source of truth is the Android build script.
OPENVPN3_COMMIT=$(grep -oE 'OPENVPN3_COMMIT=[0-9a-f]+' "$REPO_ROOT/android/openvpn3/build-openvpn3-android.sh" | head -1 | cut -d= -f2)
if [ -z "$OPENVPN3_COMMIT" ]; then
  echo "RIG_FATAL=cannot read OPENVPN3_COMMIT from build-openvpn3-android.sh"
  exit 2
fi

# SoftEther legacy pin (diagnosis §10): 4.29's OpenVPN clone
# predates client-certificate capture (its Interop_OpenVPN.c
# builds the TLS pipe without the cert_verify callback 4.38+
# added), so a certificate-only pool session can only be
# refused — the legacy section below reproduces that
# AUTH_FAILED signature as a pinned known-defect gate.
SOFTETHER_OLD_TAG=v4.29-9680-rtm
SOFTETHER_OLD_TARBALL=softether-vpnserver-v4.29-9680-rtm-2019.02.28-linux-x64-64bit.tar.gz
SOFTETHER_OLD_URL=https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/$SOFTETHER_OLD_TAG/$SOFTETHER_OLD_TARBALL
SOFTETHER_OLD_SHA256=700e4dc58a263cd8e97ea66d3744c29648bc5f1aa9f0e355ed43fb6ca4022dd7
SE_OLD_DIR="$WORK/softether-old/vpnserver"

# SoftEther ports: the OpenVPN clone rides the server's main
# TCP listeners; the rig uses 1194 (a default listener).
SE_DIR="$WORK/softether/vpnserver"
# Admin target for every vpncmd call. vpncmd given a bare host
# dials port 443 — and 443/992 are privileged ports: for the
# non-root CI user they NEVER bind (the server logs "Unable to
# set port to Listen status ... Attempting at fixed intervals
# until successful" once, at the head of its log, then retries
# forever), so a bare-host vpncmd fails with Error code 1 no
# matter how long the rig waits (run 43595049936 burned the
# full 900s deadline this way while raw TCP probes to 5555
# kept succeeding). The admin RPC is accepted on every
# listener, so address the unprivileged 5555 listener
# explicitly; it binds for root and non-root alike.
SE_ADMIN_HOST=127.0.0.1:5555
CTRL_A_PORT=1195
RELAY_CORE_PORT=1196
RELAY_REF_PORT=1197

FAILURES=0
BG_PIDS=""

note() { echo "== $* =="; }
gate() { # gate <name> <0|1>
  echo "RIG_GATE_$1=$2"
  if [ "$2" != "1" ]; then FAILURES=$((FAILURES + 1)); fi
}
record() { echo "RIG_$1=$2"; }

cleanup() {
  for pid in $BG_PIDS; do kill "$pid" 2>/dev/null || true; done
  if [ -x "$SE_DIR/vpnserver" ]; then (cd "$SE_DIR" && ./vpnserver stop >/dev/null 2>&1) || true; fi
  if [ -x "$SE_OLD_DIR/vpnserver" ]; then (cd "$SE_OLD_DIR" && ./vpnserver stop >/dev/null 2>&1) || true; fi
  cp -f "$WORK"/*.log "$OUT/" 2>/dev/null || true
}
trap cleanup EXIT

for tool in go javac java swig cmake git openssl openvpn python3 curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "RIG_FATAL=missing tool: $tool"
    exit 2
  fi
done
export JAVA_HOME=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(which javac)")")")}
echo "RIG_WORK=$WORK"
echo "RIG_JAVA_HOME=$JAVA_HOME"
echo "RIG_OPENVPN3_COMMIT=$OPENVPN3_COMMIT"

# ---------------------------------------------------------------
note "fetch + build SoftEther $SOFTETHER_TAG"
# ---------------------------------------------------------------
if [ ! -x "$SE_DIR/vpnserver" ]; then
  mkdir -p "$WORK/softether"
  curl -sL -o "$WORK/softether/se.tar.gz" "$SOFTETHER_URL"
  echo "$SOFTETHER_SHA256  $WORK/softether/se.tar.gz" | sha256sum -c - || {
    echo "RIG_FATAL=SoftEther tarball sha256 mismatch"; exit 2; }
  tar -xzf "$WORK/softether/se.tar.gz" -C "$WORK/softether"
  # The stable tarball's make is non-interactive in this
  # release line; the answers are fed anyway (older lines ask
  # a three-question license confirmation: read=1, read-it=1,
  # agree=1) and are simply unused input if not asked.
  (cd "$SE_DIR" && printf '1\n1\n1\n' | make > "$WORK/softether-make.log" 2>&1) || {
    echo "RIG_FATAL=SoftEther build failed (see softether-make.log)"; exit 2; }
fi
# se_diag dumps the SoftEther server's observable state for
# post-mortem diagnosis: the process table entry, listening
# sockets, the tail of the start log and of the last admin
# probe, and the tails of the server's own logs when present.
# Output goes to stdout (the CI step log) and to
# $WORK/se-diagnostics.log (copied into the rig artifacts).
se_diag() {
  {
    echo "--- se_diag $(date -u +%Y-%m-%dT%H:%M:%SZ) ---"
    echo "[processes]"
    ps aux 2>/dev/null | grep -i "[v]pnserver" || echo "(no vpnserver process)"
    echo "[server process elapsed / CPU time]"
    # CPU time separates "still busy initializing" (e.g. first
    # -start key generation burning CPU) from "idle but stuck"
    # (e.g. waiting on a listener that will never bind).
    ps -C vpnserver -o pid=,etime=,time=,args= 2>/dev/null || echo "(no vpnserver process found, or ps -C unsupported)"
    echo "[listening sockets]"
    (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || echo "(no ss/netstat)") | head -40
    echo "[softether-start.log tail]"
    tail -n 50 "$WORK/softether-start.log" 2>/dev/null || echo "(missing)"
    echo "[se-openvpnget.log tail]"
    tail -n 20 "$WORK/se-openvpnget.log" 2>/dev/null || echo "(missing)"
    echo "[se-tls-probe.log tail]"
    tail -n 25 "$WORK/se-tls-probe.log" 2>/dev/null || echo "(missing)"
    for d in "$SE_DIR"/*_log; do
      [ -d "$d" ] || continue
      for f in "$d"/*.log; do
        [ -f "$f" ] || continue
        # The head carries the startup record (version banner,
        # listener start lines and any "Unable to set port to
        # Listen status" failures); the tail alone hid the
        # privileged-port root cause in run 43595049936.
        echo "[server log head: $f]"
        head -n 60 "$f" 2>/dev/null
        echo "[server log tail: $f]"
        tail -n 30 "$f" 2>/dev/null
      done
    done
  } | tee "$WORK/se-diagnostics.log"
}

# se_port_open <port>: raw TCP connect probe against the
# loopback — layer 1 of the readiness wait below (is a
# listener accepting at all yet?). Readiness itself is
# decided solely by a real admin command succeeding.
se_port_open() { timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }

"$SE_DIR/vpnserver" start > "$WORK/softether-start.log" 2>&1 || true
# Bounded, LAYERED readiness wait. "vpnserver start" returns
# as soon as the daemon is spawned, but the listeners bind
# asynchronously. Readiness is probed in three layers, each
# recording its first-success time so a failure names the
# layer it died in instead of one opaque timeout:
#   layer 1 TCP   — a raw connect to the 5555 listener lands;
#   layer 2 TLS   — openssl s_client completes a handshake
#                   against 5555 and is presented a certificate
#                   (separates "socket bound" from "TLS stack
#                   and server certificate actually up");
#   layer 3 ADMIN — a real vpncmd command (OpenVpnGet)
#                   succeeds against $SE_ADMIN_HOST.
# The gate is layer 3 alone, unchanged: the wait never treats
# a lower layer as readiness, never retries a configuration
# or handshake step, and expiry is a hard failure with
# diagnostics, never a pass. SE_WAIT_DEADLINE (seconds) may
# override the bound.
#
# History: run 43593096262 hit asynchronously binding
# listeners with a fixed-count loop; run 43595049936 then
# burned the full 900s because vpncmd's bare-host default
# port (443) never binds for the non-root runner user — see
# SE_ADMIN_HOST above. The layered records exist so the next
# failure is locatable from the run alone.
SE_WAIT_DEADLINE=${SE_WAIT_DEADLINE:-900}
se_start=$(date +%s)
se_deadline=$(( se_start + SE_WAIT_DEADLINE ))
se_ready=0
se_attempt=0
se_tcp_at=""
se_tls_at=""
# se_tls_probe: 0 iff a TLS handshake against the admin
# listener completes and the server presents a certificate.
# s_client's exit status alone is not the criterion (it can
# be 0 despite a failed session), and neither is a bare
# "Cipher is" substring: a failed handshake still prints
# "Cipher is (NONE)". The handshake evidence is the peer
# certificate block plus a negotiated cipher NAME.
se_tls_probe() {
  echo | timeout 6 openssl s_client -connect 127.0.0.1:5555 >"$WORK/se-tls-probe.log" 2>&1
  grep -q -- "-----BEGIN CERTIFICATE-----" "$WORK/se-tls-probe.log" \
    && grep -qE "Cipher is [A-Za-z0-9]" "$WORK/se-tls-probe.log"
}
while :; do
  se_attempt=$((se_attempt + 1))
  se_now=$(date +%s)
  se_elapsed=$(( se_now - se_start ))
  if [ -z "$se_tcp_at" ] && se_port_open 5555; then
    se_tcp_at=$se_elapsed
    echo "RIG_READY_TCP elapsed=${se_elapsed}s attempt=$se_attempt"
  fi
  if [ -n "$se_tcp_at" ] && [ -z "$se_tls_at" ] && se_tls_probe; then
    se_tls_at=$se_elapsed
    echo "RIG_READY_TLS elapsed=${se_elapsed}s attempt=$se_attempt"
  fi
  if timeout 10 "$SE_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER /CMD OpenVpnGet </dev/null >"$WORK/se-openvpnget.log" 2>&1; then
    se_ready=1
    # A successful admin session implies the lower layers;
    # backfill any layer the probe order skipped so the
    # record is complete.
    [ -z "$se_tcp_at" ] && se_tcp_at=$se_elapsed
    [ -z "$se_tls_at" ] && se_tls_at=$se_elapsed
    echo "RIG_READY_ADMIN elapsed=${se_elapsed}s attempts=$se_attempt"
    echo "RIG_SOFTETHER_READY attempts=$se_attempt tcp_at=${se_tcp_at}s tls_at=${se_tls_at}s admin_at=${se_elapsed}s"
    break
  fi
  if [ "$se_now" -ge "$se_deadline" ]; then
    echo "RIG_FATAL=SoftEther admin interface not ready within ${SE_WAIT_DEADLINE}s ($se_attempt probes): layers tcp=${se_tcp_at:-never} tls=${se_tls_at:-never} admin=never"
    break
  fi
  if [ $((se_attempt % 6)) = "0" ]; then
    echo "RIG_WAITING=softether readiness attempt=$se_attempt elapsed=${se_elapsed}s tcp=${se_tcp_at:-pending} tls=${se_tls_at:-pending} admin=pending"
  fi
  sleep 5
done
gate SOFTETHER_UP "$se_ready"
if [ "$se_ready" != "1" ]; then
  se_diag
  echo "RIG_FATAL=SoftEther did not come up"
  exit 2
fi

vpncmd() { timeout 30 "$SE_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER "$@" </dev/null 2>&1; }
# vpncmd parses any token starting with '/' as a switch, so a
# file argument must never be an absolute POSIX path: run the
# file-taking commands from $WORK with bare relative names.
vpncmd_file() { (cd "$WORK" && timeout 30 "$SE_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER "$@" </dev/null 2>&1); }

note "configure SoftEther hub (VPN Gate shape)"
vpncmd /CMD OpenVpnEnable yes > "$WORK/se-cfg-openvpn.log" 2>&1
vpncmd_file /CMD ServerCertGet server-cert.pem > "$WORK/se-cfg-cert.log" 2>&1

# Shared client certificate pair, shaped like VPN Gate's
# distributed client cert (self-signed, CN=VPNGateClientCert).
if [ ! -f "$WORK/client-cert.pem" ]; then
  openssl genrsa -traditional -out "$WORK/client-key.pem" 2048 2>/dev/null
  openssl req -new -x509 -key "$WORK/client-key.pem" -out "$WORK/client-cert.pem" \
    -days 3650 -subj "/CN=VPNGateClientCert/C=JP" 2>/dev/null
fi
vpncmd_file /HUB:DEFAULT /CMD CAAdd client-cert.pem > "$WORK/se-cfg-caadd.log" 2>&1
vpncmd /HUB:DEFAULT /CMD UserCreate VPNGateClientCert /GROUP:none /REALNAME:none /NOTE:none > "$WORK/se-cfg-user.log" 2>&1
printf 'VPNGateClientCert\n\n' | timeout 30 "$SE_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER /HUB:DEFAULT /CMD UserSignedSet VPNGateClientCert > "$WORK/se-cfg-signed.log" 2>&1
vpncmd /HUB:DEFAULT /CMD SecureNatEnable > "$WORK/se-cfg-nat.log" 2>&1
auth_type=$(vpncmd /HUB:DEFAULT /CMD UserGet VPNGateClientCert | grep -i "Auth Type" | grep -ci "Signed Certificate" || true)
hub_ok=1
for f in se-cfg-cert se-cfg-caadd se-cfg-signed; do
  grep -q "completed successfully" "$WORK/$f.log" || hub_ok=0
done
[ "$auth_type" -ge 1 ] || hub_ok=0
if [ "$hub_ok" != "1" ]; then
  # A configuration step failed: leave the per-step evidence
  # and the server's live state in the step log and the
  # artifacts so the next failure is locatable from the run
  # alone (previously only the last readiness probe's output
  # survived). The gate below still records the failure.
  echo "== SoftEther hub configuration FAILED; per-step logs and server state follow =="
  for f in se-cfg-openvpn se-cfg-cert se-cfg-caadd se-cfg-user se-cfg-signed se-cfg-nat; do
    echo "--- $f.log (tail) ---"
    tail -n 15 "$WORK/$f.log" 2>/dev/null || echo "(missing)"
  done
  se_diag
fi
gate SOFTETHER_HUB_CONFIG "$hub_ok"

# ---------------------------------------------------------------
note "build production core (host variant) + SWIG bindings"
# ---------------------------------------------------------------
SRC="$WORK/openvpn3"
if [ ! -d "$SRC/.git" ]; then
  git clone -q https://github.com/OpenVPN/openvpn3.git "$SRC"
fi
git -C "$SRC" checkout -q "$OPENVPN3_COMMIT"
# Relavia downstream patches — the rig must test the core the
# APK actually ships, which is the pinned tree plus
# android/openvpn3/patches/ (applied by the Android build
# script the same way; see 0001-tls-version-max.patch and
# diagnosis §10). The reverse check keeps re-runs over a
# reused $RIG_WORK idempotent.
for p in "$REPO_ROOT/android/openvpn3/patches/"*.patch; do
  [ -e "$p" ] || continue
  if git -C "$SRC" apply --check "$p" 2>/dev/null; then
    git -C "$SRC" apply "$p"
  elif ! git -C "$SRC" apply --reverse --check "$p" 2>/dev/null; then
    echo "RIG_FATAL=downstream patch does not apply: $p"
    exit 2
  fi
done
GEN="$WORK/gen"
mkdir -p "$GEN/java"
swig -c++ -java -package net.openvpn.ovpn3 \
  -outdir "$GEN/java" -o "$GEN/ovpncli_wrap.cpp" \
  -I"$SRC" -I"$SRC/client" "$SRC/client/ovpncli.i" > "$WORK/swig.log" 2>&1 || {
  echo "RIG_FATAL=swig failed"; exit 2; }
BUILD="$WORK/build-host"
cmake -S "$REPO_ROOT/android/openvpn3" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENVPN3_SRC="$SRC" -DVCPKG_INSTALLED_DIR=/usr \
  > "$WORK/cmake-configure.log" 2>&1 || { echo "RIG_FATAL=cmake configure failed"; exit 2; }
# The generated wrapper is a build input of the glue
# CMakeLists; stage it where the build expects it (same as
# the Android build script).
cp "$GEN/ovpncli_wrap.cpp" "$GEN/ovpncli_wrap.h" "$BUILD/"
cmake --build "$BUILD" -j > "$WORK/core-build.log" 2>&1 || {
  echo "RIG_FATAL=core build failed"; exit 2; }
gate CORE_BUILT "$([ -f "$BUILD/libovpn3android.so" ] && echo 1 || echo 0)"

(cd "$REPO_ROOT/core" && go build -o "$WORK/rigprofile" ./openvpn/rigprofile) || {
  echo "RIG_FATAL=rigprofile build failed"; exit 2; }
javac -encoding UTF-8 -d "$WORK/classes" "$GEN"/java/*.java \
  "$RIG_DIR/Ovpn3LoopbackRig.java" > "$WORK/javac.log" 2>&1 || {
  echo "RIG_FATAL=javac failed"; exit 2; }

# ---------------------------------------------------------------
note "synthesize VPN Gate-shaped fixture + render via production path"
# ---------------------------------------------------------------
python3 - "$WORK" <<'PYEOF' || { echo "RIG_FATAL=fixture synthesis failed"; exit 2; }
import base64, pathlib, sys
work = pathlib.Path(sys.argv[1])
ca = (work / "server-cert.pem").read_text().strip()
cert = (work / "client-cert.pem").read_text().strip()
key = (work / "client-key.pem").read_text().strip()
# Directive skeleton mirrors the official VPN Gate client
# document (the local proof used a genuine document with only
# the remote line and the three PEM blocks swapped; CI uses
# this synthetic twin of identical directive shape).
doc = f"""# Synthetic VPN Gate-shaped fixture for the loopback rig.
client
dev tun
proto tcp
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
data-ciphers AES-128-CBC
auth SHA1
verb 3
<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
"""
(work / "fixture.ovpn").write_text(doc)
b64 = base64.b64encode(doc.encode()).decode()
hdr = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
row = f"rig-softether,127.0.0.1,1000000,10,1000000,Japan,JP,1,1000,1,1000,2weeks,Rig,Test,{b64}"
(work / "rig.csv").write_text("*vpn_servers\n" + hdr + "\n" + row + "\n*\n")
print("fixture synthesized")
PYEOF
"$WORK/rigprofile" -csv "$WORK/rig.csv" -out "$WORK/rendered.ovpn" > "$WORK/render.log" 2>&1 || {
  echo "RIG_FATAL=RenderProfile failed"; exit 2; }
# Render invariant: production output differs from the source
# document only by the resolv-retry rewrite, the pool TLS
# ceiling appended for pool-provenance nodes (diagnosis §10)
# and a trailing blank line (all strip out below before the
# diff).
strip_render_noise() { printf '%s' "$(grep -v '^resolv-retry' "$1" | grep -v '^tls-version-max')"; }
if diff <(strip_render_noise "$WORK/fixture.ovpn") \
        <(strip_render_noise "$WORK/rendered.ovpn") > "$WORK/render-diff.log" 2>&1; then
  gate RENDER_INVARIANT 1
else
  gate RENDER_INVARIANT 0
fi

run_driver() { # run_driver <profile> <log> [extra driver args...]
  local profile=$1 log=$2; shift 2
  timeout 90 java --add-opens java.base/sun.nio.ch=ALL-UNNAMED \
    --add-opens java.base/java.io=ALL-UNNAMED \
    -cp "$WORK/classes" Ovpn3LoopbackRig \
    --library "$BUILD/libovpn3android.so" \
    --profile "$profile" --timeout 45 "$@" > "$log" 2>&1
  return $?
}

# ---------------------------------------------------------------
note "main run: production core x SoftEther (production parity)"
# ---------------------------------------------------------------
run_driver "$WORK/rendered.ovpn" "$WORK/main-softether.log"
main_rc=$?
iv_has_cbc=$(grep -c "^RIG_IV_CIPHERS=.*AES-128-CBC" "$WORK/main-softether.log" || true)
gate PEER_INFO_ADVERTISES_CBC "$([ "$iv_has_cbc" -ge 1 ] && echo 1 || echo 0)"
gate MAIN_SOFTETHER_PASS "$([ "$main_rc" = "0" ] && grep -q "^RIG_RESULT=PASS" "$WORK/main-softether.log" && echo 1 || echo 0)"
# The main run consumes the production-rendered pool profile,
# which carries the pool TLS ceiling (diagnosis §10): with
# the downstream core patch applied the session must have
# negotiated TLS 1.2 — this gate is what proves the patch is
# present and effective in the shipped core, not just in the
# patch file.
gate TLS_CAP_NEGOTIATED_12 "$(grep -q "TLSv1\.2" "$WORK/main-softether.log" && echo 1 || echo 0)"
sec_log="$SE_DIR/security_log/DEFAULT/sec_$(date +%Y%m%d).log"
se_session=$(grep -ci "VPNGateClientCert-\[OPENVPN_L3\]" "$sec_log" 2>/dev/null || true)
gate SOFTETHER_SIDE_SESSION "$([ "${se_session:-0}" -ge 1 ] && echo 1 || echo 0)"

note "bisect record: pre-fix AEAD-only Peer Info x SoftEther"
run_driver "$WORK/rendered.ovpn" "$WORK/bisect-aead-only.log" --aead-only-peer-info 1
if grep -q "^RIG_RESULT=PASS" "$WORK/bisect-aead-only.log"; then
  record BISECT_AEAD_ONLY PASS_on_this_server
else
  record BISECT_AEAD_ONLY FAIL_on_this_server
fi

note "record: uncapped profile (pool TLS ceiling stripped) x SoftEther"
# The ceiling is a pool-session compatibility measure, not a
# core limitation: with it stripped, the patched core must
# still complete at TLS 1.3 against the modern server.
grep -v '^tls-version-max' "$WORK/rendered.ovpn" > "$WORK/rendered-uncapped.ovpn"
run_driver "$WORK/rendered-uncapped.ovpn" "$WORK/uncapped-softether.log"
uncapped_rc=$?
gate UNCAPPED_TLS13_PASS "$([ "$uncapped_rc" = "0" ] && grep -q "^RIG_RESULT=PASS" "$WORK/uncapped-softether.log" && grep -q "TLSv1\.3" "$WORK/uncapped-softether.log" && echo 1 || echo 0)"

# ---------------------------------------------------------------
note "control A: production core x genuine OpenVPN 2.6 server"
# ---------------------------------------------------------------
mkdir -p "$WORK/ctrl-a"
(
  cd "$WORK/ctrl-a"
  openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/CN=RigTestCA" 2>/dev/null
  openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=rig-server-a" 2>/dev/null
  printf "extendedKeyUsage=serverAuth\n" > srv.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -extfile srv.ext 2>/dev/null
  openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=VPNGateClientCert" 2>/dev/null
  printf "extendedKeyUsage=clientAuth\n" > cli.ext
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650 -extfile cli.ext 2>/dev/null
)
python3 - "$WORK" <<'PYEOF' || { echo "RIG_FATAL=control-A fixture synthesis failed"; exit 2; }
import base64, pathlib, re, sys
work = pathlib.Path(sys.argv[1])
ca = (work / "ctrl-a/ca.crt").read_text().strip()
cert = (work / "ctrl-a/client.crt").read_text().strip()
key = (work / "ctrl-a/client.key").read_text().strip()
doc = (work / "fixture.ovpn").read_text()
doc = doc.replace("remote 127.0.0.1 1194", "remote 127.0.0.1 1195")
doc = re.sub(r"<ca>\n.*?\n</ca>", "<ca>\n" + ca + "\n</ca>", doc, flags=re.S)
doc = re.sub(r"<cert>\n.*?\n</cert>", "<cert>\n" + cert + "\n</cert>", doc, flags=re.S)
doc = re.sub(r"<key>\n.*?\n</key>", "<key>\n" + key + "\n</key>", doc, flags=re.S)
(work / "ctrl-a/fixture-a.ovpn").write_text(doc)
b64 = base64.b64encode(doc.encode()).decode()
hdr = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
row = f"rig-openvpn,127.0.0.1,1000000,10,1000000,Japan,JP,1,1000,1,1000,2weeks,Rig,Test,{b64}"
(work / "ctrl-a/rig-a.csv").write_text("*vpn_servers\n" + hdr + "\n" + row + "\n*\n")
print("control-A fixture synthesized")
PYEOF
"$WORK/rigprofile" -csv "$WORK/ctrl-a/rig-a.csv" -out "$WORK/ctrl-a/rendered-a.ovpn" >> "$WORK/render.log" 2>&1
cat > "$WORK/ctrl-a/server-a.conf" <<EOF
port $CTRL_A_PORT
proto tcp-server
tls-server
dev null
ifconfig-noexec
route-noexec
ca $WORK/ctrl-a/ca.crt
cert $WORK/ctrl-a/server.crt
key $WORK/ctrl-a/server.key
dh none
cipher AES-128-CBC
data-ciphers AES-128-CBC
auth SHA1
ifconfig 10.8.0.1 10.8.0.2
push "ifconfig 10.8.0.2 10.8.0.1"
verb 4
EOF
openvpn --config "$WORK/ctrl-a/server-a.conf" > "$WORK/ctrl-a/server-a.log" 2>&1 &
BG_PIDS="$BG_PIDS $!"
for _ in $(seq 1 20); do
  grep -q "Listening for incoming" "$WORK/ctrl-a/server-a.log" && break
  sleep 1
done
run_driver "$WORK/ctrl-a/rendered-a.ovpn" "$WORK/ctrl-a/main-a.log"
ctrl_a_rc=$?
gate CONTROL_A_OPENVPN_PASS "$([ "$ctrl_a_rc" = "0" ] && grep -q "^RIG_RESULT=PASS" "$WORK/ctrl-a/main-a.log" && echo 1 || echo 0)"

# ---------------------------------------------------------------
note "control B + first-packet byte comparison (via byte relays)"
# ---------------------------------------------------------------
sed "s/^remote 127.0.0.1 1194/remote 127.0.0.1 $RELAY_CORE_PORT/" "$WORK/rendered.ovpn" > "$WORK/rendered-relay-core.ovpn"
sed "s/^remote 127.0.0.1 1194/remote 127.0.0.1 $RELAY_REF_PORT/" "$WORK/rendered.ovpn" > "$WORK/rendered-relay-ref.ovpn"
python3 "$RIG_DIR/byte_relay.py" $RELAY_CORE_PORT 1194 "$WORK/cap-core" > "$WORK/relay-core.log" 2>&1 &
BG_PIDS="$BG_PIDS $!"
python3 "$RIG_DIR/byte_relay.py" $RELAY_REF_PORT 1194 "$WORK/cap-ref" > "$WORK/relay-ref.log" 2>&1 &
BG_PIDS="$BG_PIDS $!"
sleep 2
run_driver "$WORK/rendered-relay-core.ovpn" "$WORK/relay-core-run.log"
relay_core_rc=$?
timeout 16 openvpn --config "$WORK/rendered-relay-ref.ovpn" \
  --dev null --ifconfig-noexec --route-noexec --verb 4 > "$WORK/relay-ref-run.log" 2>&1 || true
sleep 1
gate RELAY_CORE_PASS "$([ "$relay_core_rc" = "0" ] && grep -q "^RIG_RESULT=PASS" "$WORK/relay-core-run.log" && echo 1 || echo 0)"
gate DESKTOP_CLIENT_PASS "$(grep -q "Initialization Sequence Completed" "$WORK/relay-ref-run.log" && echo 1 || echo 0)"
if [ -f "$WORK/cap-core.c2s.bin" ] && [ -f "$WORK/cap-ref.c2s.bin" ]; then
  python3 "$RIG_DIR/compare_first_packet.py" "$WORK/cap-core.c2s.bin" "$WORK/cap-ref.c2s.bin" 1194 \
    > "$WORK/first-packet-compare.log" 2>&1
  gate FIRST_PACKET_IDENTICAL "$(grep -q "^FIRST_PACKET_IDENTICAL_EXCLUDING_SESSION_ID=1" "$WORK/first-packet-compare.log" && echo 1 || echo 0)"
else
  echo "RIG_COMPARE=skipped (relay captures missing)"
  gate FIRST_PACKET_IDENTICAL 0
fi

# ---------------------------------------------------------------
note "legacy reproduction: production core x SoftEther 4.29 (known-defect gate)"
# ---------------------------------------------------------------
# Diagnosis §10: 4.29's OpenVPN clone never captures the
# client certificate (no cert_verify callback on its TLS
# pipe), so a certificate-only pool session is classified as
# "external server authentication" with an empty user name
# and refused with AUTH_FAILED after Session is ACTIVE —
# the 2026-11-15 real-device signature. The production
# profile (pool TLS ceiling included: 4.29 negotiates
# TLS 1.2 anyway) must reproduce that failure EXACTLY. If
# this gate ever flips, §10's conclusion is stale and must
# be revisited before anyone celebrates.
(cd "$SE_DIR" && ./vpnserver stop >/dev/null 2>&1) || true
sleep 2
if [ ! -x "$SE_OLD_DIR/vpnserver" ]; then
  mkdir -p "$WORK/softether-old"
  curl -sL -o "$WORK/softether-old/se.tar.gz" "$SOFTETHER_OLD_URL"
  echo "$SOFTETHER_OLD_SHA256  $WORK/softether-old/se.tar.gz" | sha256sum -c - || {
    echo "RIG_FATAL=SoftEther 4.29 tarball sha256 mismatch"; exit 2; }
  tar -xzf "$WORK/softether-old/se.tar.gz" -C "$WORK/softether-old"
  (cd "$SE_OLD_DIR" && printf '1\n1\n1\n' | make > "$WORK/softether-old-make.log" 2>&1) || {
    echo "RIG_FATAL=SoftEther 4.29 build failed (see softether-old-make.log)"; exit 2; }
fi
"$SE_OLD_DIR/vpnserver" start > "$WORK/softether-old-start.log" 2>&1 || true
old_ready=0
for _ in $(seq 1 60); do
  if timeout 10 "$SE_OLD_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER /CMD OpenVpnGet </dev/null >"$WORK/se-old-openvpnget.log" 2>&1; then
    old_ready=1
    break
  fi
  sleep 5
done
gate LEGACY_SOFTETHER_UP "$old_ready"
if [ "$old_ready" = "1" ]; then
  vpncmd_old() { timeout 30 "$SE_OLD_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER "$@" </dev/null 2>&1; }
  vpncmd_old_file() { (cd "$WORK" && timeout 30 "$SE_OLD_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER "$@" </dev/null 2>&1); }
  vpncmd_old /CMD OpenVpnEnable yes > "$WORK/se-old-cfg-openvpn.log" 2>&1
  vpncmd_old_file /CMD ServerCertGet server-cert-old.pem > "$WORK/se-old-cfg-cert.log" 2>&1
  vpncmd_old_file /HUB:DEFAULT /CMD CAAdd client-cert.pem > "$WORK/se-old-cfg-caadd.log" 2>&1
  vpncmd_old /HUB:DEFAULT /CMD UserCreate VPNGateClientCert /GROUP:none /REALNAME:none /NOTE:none > "$WORK/se-old-cfg-user.log" 2>&1
  printf 'VPNGateClientCert\n\n' | timeout 30 "$SE_OLD_DIR/vpncmd" "$SE_ADMIN_HOST" /SERVER /HUB:DEFAULT /CMD UserSignedSet VPNGateClientCert > "$WORK/se-old-cfg-signed.log" 2>&1
  vpncmd_old /HUB:DEFAULT /CMD SecureNatEnable > "$WORK/se-old-cfg-nat.log" 2>&1
  old_auth_type=$(vpncmd_old /HUB:DEFAULT /CMD UserGet VPNGateClientCert | grep -i "Auth Type" | grep -ci "Signed Certificate" || true)
  gate LEGACY_SOFTETHER_HUB_CONFIG "$([ "${old_auth_type:-0}" -ge 1 ] && echo 1 || echo 0)"
  python3 - "$WORK" <<'PYEOF' || { echo "RIG_FATAL=legacy fixture synthesis failed"; exit 2; }
import base64, pathlib, re, sys
work = pathlib.Path(sys.argv[1])
ca = (work / "server-cert-old.pem").read_text().strip()
doc = (work / "fixture.ovpn").read_text()
doc = re.sub(r"<ca>\n.*?\n</ca>", "<ca>\n" + ca + "\n</ca>", doc, flags=re.S)
(work / "fixture-old.ovpn").write_text(doc)
b64 = base64.b64encode(doc.encode()).decode()
hdr = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
row = f"rig-softether-old,127.0.0.1,1000000,10,1000000,Japan,JP,1,1000,1,1000,2weeks,Rig,Test,{b64}"
(work / "rig-old.csv").write_text("*vpn_servers\n" + hdr + "\n" + row + "\n*\n")
print("legacy fixture synthesized")
PYEOF
  "$WORK/rigprofile" -csv "$WORK/rig-old.csv" -out "$WORK/rendered-old.ovpn" >> "$WORK/render.log" 2>&1 || {
    echo "RIG_FATAL=legacy RenderProfile failed"; exit 2; }
  sec_old="$SE_OLD_DIR/security_log/DEFAULT/sec_$(date +%Y%m%d).log"
  sec_old_before=0
  [ -f "$sec_old" ] && sec_old_before=$(wc -l < "$sec_old")
  run_driver "$WORK/rendered-old.ovpn" "$WORK/legacy-429.log"
  legacy_rc=$?
  record LEGACY_429_DRIVER_RC "$legacy_rc"
  gate LEGACY_429_AUTH_FAILED_SIGNATURE "$([ "$legacy_rc" != "0" ] && grep -q "Session is ACTIVE" "$WORK/legacy-429.log" && grep -q "AUTH_FAILED" "$WORK/legacy-429.log" && echo 1 || echo 0)"
  old_sig=0
  if [ -f "$sec_old" ]; then
    old_sig=$(tail -n "+$((sec_old_before + 1))" "$sec_old" | grep -c "External server authentication" || true)
  fi
  gate LEGACY_429_SERVER_SIGNATURE "$([ "${old_sig:-0}" -ge 1 ] && echo 1 || echo 0)"
  (cd "$SE_OLD_DIR" && ./vpnserver stop >/dev/null 2>&1) || true
fi

# ---------------------------------------------------------------
note "summary"
# ---------------------------------------------------------------
cp -f "$WORK"/ctrl-a/*.log "$OUT/" 2>/dev/null || true
if [ "$FAILURES" = "0" ]; then
  echo "RIG_RESULT=PASS"
  exit 0
fi
echo "RIG_RESULT=FAIL failures=$FAILURES"
exit 1
