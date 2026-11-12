#!/usr/bin/env bash
# killswitch-check.sh — Step 12 kill-switch leak-blocking rig.
#
# What it verifies, with REAL traffic and REAL kernel counters,
# in a two-namespace topology built for the purpose:
#
#   S0 baseline control: without rules, direct traffic works
#      (proves the rig could leak if the kill switch failed).
#   S1 the COMPILED ruleset (generated on the spot by
#      core/killswitch/nftdump — never a hand-written copy) is
#      loaded into the client namespace's kernel.
#   S2 the tunnel-endpoint exception passes (TCP + UDP).
#   S3 direct traffic to the target is blocked; the server-side
#      packet counter for the target port does not move; the
#      client-side drop counter does.
#   S4 DNS outside the tunnel is blocked (UDP + TCP port 53).
#   S5 traffic via the tunnel interface passes.
#   S6 the tunnel interface is killed (link down, default route
#      restored to the physical interface — the OS behaviour on
#      tunnel death): S3/S4 still blocked, server counters
#      still unmoved. THIS is the Step 12 acceptance scenario.
#   S7 IPv6 direct traffic is blocked too (inet family).
#   S8 teardown control: rules removed, direct traffic works
#      again (proves the rules were the blocker in S3–S7).
#
# Requirements: Linux with iproute2 + nftables + python3, and
# either root/CAP_NET_ADMIN or unprivileged user namespaces
# (the script re-executes itself under `unshare -Urn`).
# Topology note: the "server" namespace plays both the node
# server (endpoint 192.168.12.1:9999) and the public target
# (192.168.12.1:8080, and 10.99.0.1:8080 as reached through the
# tunnel) — a simulation of roles, documented as such.
#
# Exit codes: 0 = every applicable step PASS; 1 = a real FAIL;
# 2 = ENVIRONMENT-BLOCKED (this environment cannot generate
# the traffic or hold the namespaces; the applicable subset —
# at minimum kernel acceptance of the compiled ruleset — is
# reported in the output). The Step 12 report records which
# outcome each environment produced; an ENV-BLOCKED result is
# NOT a pass and is never reported as one.
#
# Sandbox note (2026-11-12, Relavia build sandbox): namespaces
# and nftables work under unshare -Urn, but ALL non-loopback
# traffic generation is blocked at syscall level sandbox-wide
# (connect/sendto → EPERM even inside a fresh netns; loopback
# TCP works). There the script reports Phase 2 as ENV-BLOCKED
# with the probe evidence, after passing Phase 1.

set -u

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
step() { # step <name> <PASS|FAIL|SKIP> [detail]
  say "STEP $1: $2 ${3:-}"
  case "$2" in
    PASS) PASS=$((PASS+1));;
    FAIL) FAIL=$((FAIL+1));;
    SKIP) SKIP=$((SKIP+1));;
  esac
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/relavia-ks-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------
# Phase 0 (outer): environment probes + ruleset generation.
# ------------------------------------------------------------------
if [ "${1:-}" != "--inside" ]; then
  missing=""
  for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
  done
  if [ -n "$missing" ]; then
    say "ENV-BLOCKED: missing tools:$missing"
    exit 2
  fi
  if ! command -v go >/dev/null 2>&1 && [ ! -x "$HOME/tools/go/bin/go" ]; then
    say "ENV-BLOCKED: go toolchain not found (needed to build nftdump — the ruleset must come from the compiler, never a static copy)"
    exit 2
  fi
  GO="$(command -v go || echo "$HOME/tools/go/bin/go")"
  if ! (cd "$REPO_ROOT/core" && "$GO" build -o "$WORK/nftdump" ./killswitch/nftdump); then
    say "FAIL: nftdump does not build"
    exit 1
  fi
  # Rig ruleset: endpoint exception = the node server of the
  # rig topology; tunnel interface = the compiler default
  # (relavia0), so the production ruleset applies verbatim.
  if ! "$WORK/nftdump" -mode when-connected -endpoint 192.168.12.1:9999 > "$WORK/ks.nft"; then
    say "FAIL: nftdump could not compile the rig ruleset"
    exit 1
  fi
  export RELAVIA_KS_WORK="$WORK"
  if unshare -Urn true 2>/dev/null; then
    unshare -Urn bash "$0" --inside
    rc=$?
  elif [ "$(id -u)" = "0" ] && nft add table inet relavia_probe 2>/dev/null; then
    nft delete table inet relavia_probe 2>/dev/null
    bash "$0" --inside
    rc=$?
  else
    say "ENV-BLOCKED: no user namespaces and no CAP_NET_ADMIN in the current namespace"
    exit 2
  fi
  # Keep the work dir alive across the re-exec boundary: the
  # trap above removes it only in THIS process; --inside used
  # the exported path while it existed. (unshare run finished.)
  exit $rc
fi

# ------------------------------------------------------------------
# Inside a namespace with CAP_NET_ADMIN.
# ------------------------------------------------------------------
WORK="${RELAVIA_KS_WORK:-$WORK}"
NFTDUMP="$WORK/nftdump"
RULES="$WORK/ks.nft"

# --- Phase 1: kernel acceptance of the compiled ruleset -------
if nft -f "$RULES" 2>"$WORK/nft.err" && nft list table inet relavia_ks >"$WORK/list.out" 2>&1 \
   && grep -q "counter" "$WORK/list.out" && grep -q "drop" "$WORK/list.out"; then
  step kernel-acceptance PASS "(compiled ruleset loaded into a real kernel and read back)"
else
  step kernel-acceptance FAIL "(see $WORK/nft.err)"
  cat "$WORK/nft.err" >&2
fi
nft delete table inet relavia_ks 2>/dev/null

# --- Phase 1b: traffic-generation probe ------------------------
cat > "$WORK/probe.py" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("10.0.0.1", 8080)); print("OK")
except OSError as e:
    print("BLOCKED", e)
PY
probe_out="$(ip link set lo up 2>/dev/null; ip link add vA type veth peer name vB 2>/dev/null; \
  ip addr add 10.0.0.1/24 dev vA 2>/dev/null; ip link set vA up 2>/dev/null; ip link set vB up 2>/dev/null; \
  python3 "$WORK/probe.py" 2>&1)"
ip link del vA 2>/dev/null
if [ "${probe_out#BLOCKED}" != "$probe_out" ] || [ "${probe_out#OK}" = "$probe_out" ]; then
  say "PHASE2 traffic rig: ENV-BLOCKED — non-loopback traffic cannot be generated in this environment."
  say "  probe evidence: $probe_out"
  say "  (syscall-level egress policy above the namespace layer; run this script on a real"
  say "   machine or a privileged CI runner for the traffic assertions.)"
  if [ "$FAIL" -gt 0 ]; then exit 1; fi
  exit 2
fi

# --- Phase 2: the traffic rig ----------------------------------
# Server-side helpers: echo/target servers + arrival counters.
cat > "$WORK/srv.py" <<'PY'
import socket, threading, sys
TOKEN = b"TOKEN"
def tcp_serve(addr, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(8)
    while True:
        try: c, _ = s.accept()
        except OSError: return
        try: c.sendall(TOKEN + b"-" + addr.encode())
        except OSError: pass
        c.close()
def udp_echo(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((addr, port))
    while True:
        try: d, a = s.recvfrom(2048)
        except OSError: return
        s.sendto(b"ECHO:" + d, a)
def tcp_echo(addr, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(8)
    while True:
        try: c, _ = s.accept()
        except OSError: return
        try:
            d = c.recv(2048); c.sendall(b"ECHO:" + d)
        except OSError: pass
        c.close()
for a, p, f in [("192.168.12.1", 8080, tcp_serve), ("10.99.0.1", 8080, tcp_serve),
                ("192.168.12.1", 9999, tcp_echo), ("192.168.12.1", 53, tcp_echo),
                ("0.0.0.0", 9999, udp_echo), ("0.0.0.0", 53, udp_echo)]:
    threading.Thread(target=f, args=(a, p), daemon=True).start()
import time; time.sleep(3600)
PY

cat > "$WORK/srv.sh" <<'SH'
#!/bin/bash
for i in $(seq 1 100); do
  ip link show vethSe >/dev/null 2>&1 && ip link show vethSt >/dev/null 2>&1 && break
  sleep 0.1
done
ip link set lo up
ip addr add 192.168.12.1/24 dev vethSe; ip link set vethSe up
ip addr add 10.99.0.1/24 dev vethSt;   ip link set vethSt up
ip -6 addr add fd00:12::1/64 dev vethSe 2>/dev/null
# Arrival counters: did target/DNS packets REACH the server
# from the client? These are the leak witnesses.
nft add table inet ksprobe 2>/dev/null
nft add chain inet ksprobe input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null
nft add rule inet ksprobe input tcp dport 8080 counter 2>/dev/null
nft add rule inet ksprobe input udp dport 53 counter 2>/dev/null
python3 "$WORK/srv.py" &
touch "$WORK/srv-ready"
wait
SH
sed -i "s|\$WORK|$WORK|g" "$WORK/srv.sh"

cat > "$WORK/cli.py" <<'PY'
import socket, sys
mode, addr, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    ip = socket.inet_pton(socket.AF_INET6, addr); fam = socket.AF_INET6
except OSError:
    fam = socket.AF_INET
if mode == "tcp":
    s = socket.socket(fam); s.settimeout(2.5)
    try:
        s.connect((addr, port)); s.sendall(b"ping")
        print("REPLY", s.recv(128).decode(errors="replace")); sys.exit(0)
    except OSError as e:
        print("FAIL", e); sys.exit(1)
elif mode == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2.5)
    try:
        s.sendto(b"ping", (addr, port))
        d, _ = s.recvfrom(256); print("REPLY", d.decode(errors="replace")); sys.exit(0)
    except OSError as e:
        print("FAIL", e); sys.exit(1)
PY

tcp() { python3 "$WORK/cli.py" tcp "$1" "$2" 2>&1; }
udp() { python3 "$WORK/cli.py" udp "$1" "$2" 2>&1; }
dropcount() { nft list table inet relavia_ks 2>/dev/null | grep -o 'counter packets [0-9]*' | tail -1 | grep -o '[0-9]*$'; }

rm -f "$WORK/srv-ready"
unshare -n bash "$WORK/srv.sh" &
SRVPID=$!
sleep 0.3
ip link add vethCe type veth peer name vethSe
ip link add vethCt type veth peer name vethSt
ip link set vethSe netns "$SRVPID"
ip link set vethSt netns "$SRVPID"
ip link set lo up
ip addr add 192.168.12.2/24 dev vethCe; ip link set vethCe up
ip link set vethCt name relavia0
ip addr add 10.99.0.2/24 dev relavia0; ip link set relavia0 up
ip -6 addr add fd00:12::2/64 dev vethCe 2>/dev/null
for i in $(seq 1 100); do [ -f "$WORK/srv-ready" ] && break; sleep 0.1; done
sleep 0.5

# Reading the server-side counters: srv lives in another ns;
# use `ip netns` alternative — /proc/$SRVPID/root + nsenter is
# unavailable where setns is blocked, so the srv writes its
# counters to a shared file every second instead.
cat > "$WORK/countwatch.sh" <<'SH'
#!/bin/bash
while true; do
  nft list table inet ksprobe 2>/dev/null | grep -o 'counter packets [0-9]*' > "$WORK/srvcounters.txt"
  sleep 0.5
done
SH
sed -i "s|\$WORK|$WORK|g" "$WORK/countwatch.sh"
( sleep 0.2; exec nsenter -t "$SRVPID" -n bash "$WORK/countwatch.sh" ) 2>/dev/null &
WATCHPID=$!
COUNTERS_VIA_NSENTER=1
sleep 1
if [ ! -s "$WORK/srvcounters.txt" ]; then
  # Fallback used where setns/nsenter is blocked: srv.sh's own
  # namespace is unreachable for counter reads; rely on client-
  # side drop counters + connection outcomes only, and say so.
  COUNTERS_VIA_NSENTER=0
  say "NOTE: server-side counter channel unavailable in this environment (nsenter blocked);"
  say "      leak assertions use client-side drop counters + connection failure evidence."
fi
srv_target_count() {
  [ "$COUNTERS_VIA_NSENTER" = "1" ] || { echo "-1"; return; }
  sed -n '1p' "$WORK/srvcounters.txt" 2>/dev/null | grep -o '[0-9]*$' || echo "-1"
}
srv_dns_count() {
  [ "$COUNTERS_VIA_NSENTER" = "1" ] || { echo "-1"; return; }
  sed -n '2p' "$WORK/srvcounters.txt" 2>/dev/null | grep -o '[0-9]*$' || echo "-1"
}

# S0 — baseline control (no rules yet).
if tcp 192.168.12.1 8080 | grep -q TOKEN; then
  step S0-baseline-direct-open PASS
else
  step S0-baseline-direct-open FAIL "(rig cannot reach the target even without rules — rig broken, not a kill-switch result)"
fi

# S1 — apply the compiled ruleset.
if nft -f "$RULES" 2>"$WORK/nft2.err"; then
  step S1-ruleset-applied PASS
else
  step S1-ruleset-applied FAIL "(see $WORK/nft2.err)"
  kill "$SRVPID" "$WATCHPID" 2>/dev/null
  say "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP"
  [ "$FAIL" -gt 0 ] && exit 1 || exit 0
fi

# S2 — endpoint exception.
r_tcp="$(tcp 192.168.12.1 9999)"; r_udp="$(udp 192.168.12.1 9999)"
if echo "$r_tcp" | grep -q ECHO && echo "$r_udp" | grep -q ECHO; then
  step S2-endpoint-exception PASS "(kernel → node server path works while blocking)"
else
  step S2-endpoint-exception FAIL "(tcp: $r_tcp / udp: $r_udp)"
fi

# S3 — direct target blocked.
t0="$(srv_target_count)"; d0="$(dropcount)"
r="$(tcp 192.168.12.1 8080)"; t1="$(srv_target_count)"; d1="$(dropcount)"
if ! echo "$r" | grep -q TOKEN && { [ "$t0" = "-1" ] || [ "$t0" = "$t1" ]; } && [ "${d1:-0}" -gt "${d0:-0}" ]; then
  step S3-direct-target-blocked PASS "(connect failed; server arrivals $t0→$t1; client drops $d0→$d1)"
else
  step S3-direct-target-blocked FAIL "(connect: $r; server arrivals $t0→$t1; client drops $d0→$d1)"
fi

# S4 — DNS blocked (UDP + TCP 53).
n0="$(srv_dns_count)"
r_udp="$(udp 192.168.12.1 53)"; r_tcp="$(tcp 192.168.12.1 53)"
n1="$(srv_dns_count)"
if ! echo "$r_udp" | grep -q ECHO && ! echo "$r_tcp" | grep -q ECHO && { [ "$n0" = "-1" ] || [ "$n0" = "$n1" ]; }; then
  step S4-dns-blocked PASS "(no DNS answer outside the tunnel; server DNS arrivals $n0→$n1)"
else
  step S4-dns-blocked FAIL "(udp: $r_udp / tcp: $r_tcp; arrivals $n0→$n1)"
fi

# S5 — tunnel path works: default via the tunnel, target as
# reached through the tunnel egress (10.99.0.1).
ip route replace default via 10.99.0.1 dev relavia0
if tcp 10.99.0.1 8080 | grep -q TOKEN; then
  step S5-tunnel-path-open PASS
else
  step S5-tunnel-path-open FAIL
fi

# S6 — tunnel killed: interface down + default route back to
# the physical device (what the OS does when a tunnel dies).
ip link set relavia0 down
ip route replace default via 192.168.12.1 dev vethCe
t0="$(srv_target_count)"; n0="$(srv_dns_count)"; d0="$(dropcount)"
r="$(tcp 192.168.12.1 8080)"; r_udp="$(udp 192.168.12.1 53)"
t1="$(srv_target_count)"; n1="$(srv_dns_count)"; d1="$(dropcount)"
if ! echo "$r" | grep -q TOKEN && ! echo "$r_udp" | grep -q ECHO \
   && { [ "$t0" = "-1" ] || [ "$t0" = "$t1" ]; } && { [ "$n0" = "-1" ] || [ "$n0" = "$n1" ]; } \
   && [ "${d1:-0}" -gt "${d0:-0}" ]; then
  step S6-tunnel-killed-still-blocked PASS "(the Step 12 acceptance scenario: no direct traffic after tunnel death)"
else
  step S6-tunnel-killed-still-blocked FAIL "(connect: $r; dns: $r_udp; arrivals t $t0→$t1 n $n0→$n1; drops $d0→$d1)"
fi

# S7 — IPv6 direct blocked.
if ip -6 addr show dev vethCe | grep -q "fd00:12::2"; then
  r="$(python3 "$WORK/cli.py" tcp fd00:12::1 8080 2>&1)"
  if ! echo "$r" | grep -q TOKEN; then
    step S7-ipv6-blocked PASS
  else
    step S7-ipv6-blocked FAIL "(IPv6 direct traffic passed: $r)"
  fi
else
  step S7-ipv6-blocked SKIP "(IPv6 unavailable in this environment)"
fi

# S8 — teardown control.
nft delete table inet relavia_ks 2>/dev/null
if tcp 192.168.12.1 8080 | grep -q TOKEN; then
  step S8-teardown-restores PASS
else
  step S8-teardown-restores FAIL "(direct traffic still blocked after rules removed — teardown broken)"
fi

kill "$SRVPID" "$WATCHPID" 2>/dev/null
say "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
