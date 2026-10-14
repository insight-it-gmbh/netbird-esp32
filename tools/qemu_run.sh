#!/usr/bin/env bash
# Run the QEMU build of the example (ESP32 + OpenCores Ethernet, QEMU user-mode networking).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/qemu_run.sh [--fresh] [SECONDS] [LOGFILE]

Runs the QEMU build of examples/basic (ESP32 with OpenCores Ethernet) for SECONDS
(default: 120) and writes the serial console to LOGFILE (default: $TMPDIR/nbl_qemu.log,
or /tmp/nbl_qemu.log). Networking is QEMU user mode: the device gets 10.0.2.15 behind
QEMU's NAT and reaches the internet through the host.

The flash image is persistent: examples/basic/flash_persist-build-qemu.bin keeps the NVS
partition (0x9000-0xF000 in the default partition table, where the device's WireGuard key
lives) across runs and rebuilds, so the device keeps its NetBird identity. Bootloader,
partition table and app are replaced from the latest build on every start.

  --fresh   start with an empty NVS partition (the device registers as a new peer and
            needs a setup key that is still valid)
  -h, --help

Only one QEMU instance per flash image can run (enforced with flock): two devices with
the same key displace each other at the management and relay servers.

Build first with: tools/build.sh qemu
QEMU: qemu-system-xtensa from PATH, otherwise the newest version installed by ESP-IDF in
$IDF_TOOLS_PATH (default ~/.espressif)/tools/qemu-xtensa/. Install it with:
  python $IDF_PATH/tools/idf_tools.py install qemu-xtensa
ESP-IDF (for esptool.py): $IDF_PATH/export.sh if IDF_PATH is set, otherwise
~/esp/esp-idf/export.sh.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

# Print the path of ESP-IDF's export.sh or fail with a hint.
find_idf_export() {
  local f
  if [ -n "${IDF_PATH:-}" ]; then
    f="$IDF_PATH/export.sh"
    [ -f "$f" ] || die "IDF_PATH is set to '$IDF_PATH', but $f does not exist"
  else
    f="$HOME/esp/esp-idf/export.sh"
    [ -f "$f" ] || die "ESP-IDF not found. Set IDF_PATH to your ESP-IDF directory or install" \
      "ESP-IDF in ~/esp/esp-idf (https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/)"
  fi
  printf '%s\n' "$f"
}

# Command prefix that runs a program with a minimal environment plus the variables ESP-IDF
# may need, so that an active Python virtualenv cannot interfere with ESP-IDF's Python.
idf_env() {
  IDF_ENV=(env -i "HOME=$HOME" "PATH=/usr/local/bin:/usr/bin:/bin" "LANG=C.UTF-8" "TERM=${TERM:-dumb}")
  local v
  while IFS= read -r v; do
    case "$v" in
      IDF_PATH | IDF_TOOLS_PATH | http_proxy | https_proxy | no_proxy | HTTP_PROXY | HTTPS_PROXY | NO_PROXY)
        IDF_ENV+=("$v=${!v}")
        ;;
    esac
  done < <(compgen -e)
}

# Print the QEMU binary: PATH first, then the newest version in the ESP-IDF tools directory.
find_qemu() {
  if command -v qemu-system-xtensa >/dev/null 2>&1; then
    command -v qemu-system-xtensa
    return 0
  fi
  local tools="${IDF_TOOLS_PATH:-$HOME/.espressif}/tools/qemu-xtensa" best
  local cands=("$tools"/*/qemu/bin/qemu-system-xtensa)
  best=$(printf '%s\n' "${cands[@]}" | sort -V | tail -n 1)
  [ -x "$best" ] || return 1
  printf '%s\n' "$best"
}

FRESH=0
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --fresh) FRESH=1 ;;
    -*)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 2
      ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ ${#POS[@]} -le 2 ] || { usage >&2; exit 2; }
SECS="${POS[0]:-120}"
LOG="${POS[1]:-${TMPDIR:-/tmp}/nbl_qemu.log}"
if ! [[ $SECS =~ ^[0-9]+$ ]] || [ "$SECS" -eq 0 ]; then
  die "SECONDS must be a positive integer, got '$SECS'"
fi
# a relative LOGFILE is relative to the caller's directory, not to examples/basic
case "$LOG" in
  /*) ;;
  *) LOG="$PWD/$LOG" ;;
esac

command -v flock >/dev/null 2>&1 || die "flock not found (part of util-linux)"
QEMU=$(find_qemu) || die "qemu-system-xtensa not found in PATH or in" \
  "${IDF_TOOLS_PATH:-$HOME/.espressif}/tools/qemu-xtensa (install: python \$IDF_PATH/tools/idf_tools.py install qemu-xtensa)"

cd "$(dirname "$0")/../examples/basic"
B=build-qemu
[ -f "$B/flash_args" ] || die "examples/basic/$B/flash_args not found - build first: tools/build.sh qemu"
PERSIST="flash_persist-$B.bin" # outside the build directory: survives rebuilds

# One instance per flash image. Take the lock before touching any image file, so that a
# second invocation cannot modify the image under a running QEMU.
exec 9>"$B/.qemu.lock"
flock -n 9 || { echo "error: a QEMU instance is already running with $PERSIST" >&2; exit 3; }

IDF_EXPORT=$(find_idf_export)
idf_env
# shellcheck disable=SC2016 # the inner script expands its variables itself
"${IDF_ENV[@]}" IDF_EXPORT="$IDF_EXPORT" B="$B" bash -c '
  log=$(mktemp)
  if ! . "$IDF_EXPORT" >"$log" 2>&1; then
    cat "$log" >&2
    rm -f "$log"
    echo "error: sourcing $IDF_EXPORT failed" >&2
    exit 1
  fi
  rm -f "$log"
  set -eo pipefail
  cd "$B"
  esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o flash_qemu.bin @flash_args >/dev/null
'

if [ "$FRESH" -eq 1 ] || [ ! -f "$PERSIST" ]; then
  cp "$B/flash_qemu.bin" "$PERSIST"
else
  # keep the NVS partition (0x9000-0xF000) of the persistent image, take everything else
  # from the new build
  python3 - "$B/flash_qemu.bin" "$PERSIST" <<'PY'
import sys

with open(sys.argv[1], "rb") as f:
    new = f.read()
with open(sys.argv[2], "rb") as f:
    old = bytearray(f.read())
if len(old) != len(new):
    sys.exit("error: flash size of %s changed - run with --fresh" % sys.argv[2])
old[:0x9000] = new[:0x9000]
old[0xF000:] = new[0xF000:]
with open(sys.argv[2], "wb") as f:
    f.write(old)
PY
fi

rm -f "$LOG"
echo "QEMU running for ${SECS} s, console log: $LOG"
rc=0
# -nic user: QEMU's default user-mode network (guest 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3)
timeout "$SECS" "$QEMU" -M esp32 -m 4M -nographic \
  -drive file="$PERSIST",if=mtd,format=raw \
  -nic user,model=open_eth \
  -global driver=timer.esp32.timg,property=wdt_disable,value=true \
  >"$LOG" 2>&1 || rc=$?
# timeout(1) exits with 124 when the time is up: that is the normal end of a run
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
  echo "error: QEMU exited with status $rc; last lines of $LOG:" >&2
  tail -n 20 "$LOG" >&2
  exit "$rc"
fi
echo "QEMU stopped, log: $LOG ($(wc -l <"$LOG") lines)"
