#!/usr/bin/env bash
# Soak test against a running netbird-lite device: ping plus periodic blob downloads.
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: tools/soak.sh DEVICE_OVERLAY_IP [MINUTES]

Long-running check from a NetBird peer (same policy requirements as tools/e2e_test.sh).
For MINUTES (default: 10) it pings the device every 3 s or so and once a minute downloads a
20 kB pattern from /blob (SHA-256 checked) and prints the device's /status JSON, so its
counters (relay_rx/relay_tx, acl_pass/acl_drop, heap, heap_min) can be followed over time.

Summary at the end: pings sent and lost, loss rate, longest run of consecutive lost pings,
blob downloads and failed downloads.
Exit status: 1 if a blob download failed or no ping was answered at all, 0 otherwise.
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
[ $# -le 2 ] || { usage >&2; exit 2; }
IP=$1
MIN=${2:-10}
if ! [[ $MIN =~ ^[0-9]+$ ]] || [ "$MIN" -eq 0 ]; then
  echo "error: MINUTES must be a positive integer, got '$MIN'" >&2
  exit 2
fi
MIN=$((10#$MIN))

END=$(($(date +%s) + MIN * 60))
sent=0
lost=0
gap=0
maxgap=0
blobs=0
blobfail=0
lastblob=0
WANT=$(python3 -c "import hashlib,sys; sys.stdout.write(hashlib.sha256(bytes(i % 251 for i in range(20000))).hexdigest())")
while [ "$(date +%s)" -lt "$END" ]; do
  sent=$((sent + 1))
  if ping -c 1 -W 2 "$IP" >/dev/null 2>&1; then
    gap=0
  else
    lost=$((lost + 1))
    gap=$((gap + 1))
    if [ "$gap" -gt "$maxgap" ]; then
      maxgap=$gap
    fi
  fi
  now=$(date +%s)
  if [ $((now - lastblob)) -ge 60 ]; then
    lastblob=$now
    blobs=$((blobs + 1))
    S=$(curl -s -m 30 "http://$IP/blob?n=20000" | sha256sum | cut -d' ' -f1)
    if [ "$S" != "$WANT" ]; then
      blobfail=$((blobfail + 1))
      echo "$(date +%T) blob download failed or corrupted"
    fi
    echo "$(date +%T) $(curl -s -m 10 "http://$IP/status")"
  fi
  sleep 3
done
LOSS=$(python3 -c "print('%.1f' % (100.0 * $lost / max($sent, 1)))")
echo "== soak $MIN min: $sent pings, $lost lost ($LOSS %), longest gap $maxgap pings," \
  "blobs $blobs (failed $blobfail) =="
[ "$blobfail" -eq 0 ] && [ "$lost" -lt "$sent" ]
