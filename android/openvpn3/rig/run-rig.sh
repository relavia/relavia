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

# SoftEther ports: the OpenVPN clone rides the server's main
# TCP listeners; the rig uses 1194 (a default listener).
SE_DIR="$WORK/softether/vpnserver"
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
"$SE_DIR/vpnserver" start > "$WORK/softether-start.log" 2>&1 || true
# Wait for the admin interface to answer.
se_ready=0
for _ in $(seq 1 30); do
  if timeout 10 "$SE_DIR/vpncmd" localhost /SERVER /CMD OpenVpnGet </dev/null >"$WORK/se-openvpnget.log" 2>&1; then
    se_ready=1; break
  fi
  sleep 2
done
gate SOFTETHER_UP "$se_ready"
[ "$se_ready" = "1" ] || { echo "RIG_FATAL=SoftEther did not come up"; exit 2; }

vpncmd() { timeout 30 "$SE_DIR/vpncmd" localhost /SERVER "$@" </dev/null 2>&1; }
# vpncmd parses any token starting with '/' as a switch, so a
# file argument must never be an absolute POSIX path: run the
# file-taking commands from $WORK with bare relative names.
vpncmd_file() { (cd "$WORK" && timeout 30 "$SE_DIR/vpncmd" localhost /SERVER "$@" </dev/null 2>&1); }

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
printf 'VPNGateClientCert\n\n' | timeout 30 "$SE_DIR/vpncmd" localhost /SERVER /HUB:DEFAULT /CMD UserSignedSet VPNGateClientCert > "$WORK/se-cfg-signed.log" 2>&1
vpncmd /HUB:DEFAULT /CMD SecureNatEnable > "$WORK/se-cfg-nat.log" 2>&1
auth_type=$(vpncmd /HUB:DEFAULT /CMD UserGet VPNGateClientCert | grep -i "Auth Type" | grep -ci "Signed Certificate" || true)
hub_ok=1
for f in se-cfg-cert se-cfg-caadd se-cfg-signed; do
  grep -q "completed successfully" "$WORK/$f.log" || hub_ok=0
done
[ "$auth_type" -ge 1 ] || hub_ok=0
gate SOFTETHER_HUB_CONFIG "$hub_ok"

# ---------------------------------------------------------------
note "build production core (host variant) + SWIG bindings"
# ---------------------------------------------------------------
SRC="$WORK/openvpn3"
if [ ! -d "$SRC/.git" ]; then
  git clone -q https://github.com/OpenVPN/openvpn3.git "$SRC"
fi
git -C "$SRC" checkout -q "$OPENVPN3_COMMIT"
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
# document only by the resolv-retry rewrite and a trailing
# blank line (both strip out below before the diff).
strip_render_noise() { printf '%s' "$(grep -v '^resolv-retry' "$1")"; }
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
note "summary"
# ---------------------------------------------------------------
cp -f "$WORK"/ctrl-a/*.log "$OUT/" 2>/dev/null || true
if [ "$FAILURES" = "0" ]; then
  echo "RIG_RESULT=PASS"
  exit 0
fi
echo "RIG_RESULT=FAIL failures=$FAILURES"
exit 1
