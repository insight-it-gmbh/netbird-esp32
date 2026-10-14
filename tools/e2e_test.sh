#!/usr/bin/env bash
# End-to-end test against a running netbird-lite device (QEMU or hardware).
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: tools/e2e_test.sh DEVICE_OVERLAY_IP

Runs end-to-end checks against the example application on a device that is connected to
NetBird. Run it from a NetBird peer that the account's policies allow to reach the device
with ICMP and TCP port 80 (tools/nb_testenv.py setup creates such policies).

Checks:
  - ping: 5 echo requests, no loss
  - GET /                  answer contains "ESP32 over NetBird"
  - POST /echo             body comes back unchanged
  - GET /blob?n=200000     SHA-256 of the byte pattern i % 251 matches (prints throughput)
  - TCP port 8081          must time out: the device runs a TCP echo service there that the
                           policy does not allow, so its firewall has to drop the SYNs
  - /status acl_drop       counter increases while port 8081 is probed
  - /status peers_up       at least 1

Exit status: 0 if all checks pass, 1 otherwise.
Requires: ping (iputils), curl, python3, sha256sum.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  "" | -*)
    usage >&2
    exit 2
    ;;
esac
[ $# -eq 1 ] || { usage >&2; exit 2; }
IP=$1

PASS=0
FAIL=0
pass() {
  echo "  PASS  $1"
  PASS=$((PASS + 1))
}
fail() {
  echo "  FAIL  $1  ($2)"
  FAIL=$((FAIL + 1))
}
is_int() { [[ $1 =~ ^[0-9]+$ ]]; }
status() { curl -s -m 10 "http://$IP/status"; }
# jget FIELD: read JSON from stdin and print FIELD (empty if missing or not JSON)
jget() {
  python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get(sys.argv[1], ""))
except Exception:
    print("")
' "$1"
}

echo "== target $IP =="

P=$(ping -c 5 -W 3 "$IP" 2>&1)
echo "$P" | tail -n 2
if [[ $P == *" 0% packet loss"* ]]; then
  pass "ICMP: 0% packet loss"
else
  fail "ICMP: 0% packet loss" "$(grep -o '[0-9.]*% packet loss' <<<"$P" || echo "no ping summary")"
fi

R=$(curl -s -m 15 "http://$IP/")
if [[ $R == *"ESP32 over NetBird"* ]]; then
  pass "HTTP GET /"
else
  fail "HTTP GET /" "got: ${R:0:120}"
fi

E=$(curl -s -m 15 --data 'e2e-echo-123' "http://$IP/echo")
if [ "$E" = "e2e-echo-123" ]; then
  pass "HTTP POST /echo (round trip)"
else
  fail "HTTP POST /echo (round trip)" "got: ${E:0:120}"
fi

N=200000
T0=$(date +%s.%N)
SUM=$(curl -s -m 120 "http://$IP/blob?n=$N" | sha256sum | cut -d' ' -f1)
T1=$(date +%s.%N)
WANT=$(python3 -c "import hashlib,sys; sys.stdout.write(hashlib.sha256(bytes(i % 251 for i in range($N))).hexdigest())")
if [ "$SUM" = "$WANT" ]; then
  pass "blob of $N bytes: SHA-256 matches"
else
  fail "blob of $N bytes: SHA-256 matches" "got $SUM"
fi
python3 -c "print('        throughput: %.0f kB/s over %.1f s' % ($N / 1000 / ($T1 - $T0), $T1 - $T0))"

D0=$(status | jget acl_drop)
RC=0
curl -s -m 6 -o /dev/null "http://$IP:8081/" || RC=$?
sleep 2
D1=$(status | jget acl_drop)
# curl exit status 28 = timeout: the SYNs were dropped. 7 (refused) or any other error
# means a packet reached the device's TCP stack, i.e. the firewall let it through.
if [ "$RC" -eq 28 ]; then
  pass "port 8081 (not allowed by the policy) is filtered"
else
  fail "port 8081 (not allowed by the policy) is filtered" "curl exit status $RC, expected 28 (timeout)"
fi
if is_int "$D0" && is_int "$D1" && [ "$D1" -gt "$D0" ]; then
  pass "ACL counter acl_drop increased ($D0 -> $D1)"
else
  fail "ACL counter acl_drop increased" "before '$D0', after '$D1'"
fi

S=$(status)
UP=$(jget peers_up <<<"$S")
if is_int "$UP" && [ "$UP" -ge 1 ]; then
  pass "status: peers_up >= 1"
else
  fail "status: peers_up >= 1" "peers_up '$UP'"
fi
echo "  status: $S"
echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
