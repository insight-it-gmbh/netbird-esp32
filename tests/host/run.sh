#!/usr/bin/env bash
# Host test suite for the platform-independent parts of netbird-lite (no ESP-IDF needed):
# unit tests under AddressSanitizer + UndefinedBehaviorSanitizer, a replay of the saved
# regression inputs and a time-boxed libFuzzer run per fuzz target.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/host/run.sh [FUZZ_SECONDS]

Builds and runs the host tests of netbird-lite:
  1. unit tests (test_units, test_h2p) with ASan + UBSan
  2. every file in tests/host/regress/*.bin replayed through every fuzz target
  3. each libFuzzer target for FUZZ_SECONDS seconds (default: 45, 0 skips this step)

Any failed check, sanitizer report or fuzzer crash makes the script exit non-zero.
On success the last line of output is "all host tests passed".

Requirements: a C11 compiler, clang with libFuzzer (compiler-rt), python3, coreutils.
Optional: llvm-symbolizer (also found under versioned names) for readable stack traces.

Environment:
  CC             compiler for the unit tests (default: cc)
  CLANG          compiler for the fuzz targets (default: clang)
  ASAN_OPTIONS   passed through unchanged
  UBSAN_OPTIONS  appended to the defaults set by this script
  DEBUGINFOD_URLS is cleared: stack traces are symbolized from local files only.

Binaries, logs and fuzzing corpora are kept in tests/host/build/. Crash inputs are saved
in tests/host/build/artifacts/. Once a bug is fixed, copy its input to
tests/host/regress/<target>-<short-hash>.bin so that every run replays it.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac
if [ $# -gt 1 ] || { [ $# -eq 1 ] && ! [[ $1 =~ ^[0-9]+$ ]]; }; then
  usage >&2
  exit 2
fi
FUZZ_SECS=$((10#${1:-45}))

cd "$(dirname "$0")"
SRC=../../components/netbird_lite/src
OUT=build
ART=$OUT/artifacts
mkdir -p "$OUT" "$ART"

CC=${CC:-cc}
CLANG=${CLANG:-clang}
CFLAGS=(-std=c11 -Wall -Wextra -O1 -g -fno-omit-frame-pointer -I"$SRC")
# -fno-sanitize-recover=all turns every UBSan report into a failure. Without it UBSan only
# prints a warning and the test binary (or fuzzer) still exits with status 0.
SAN=("-fsanitize=address,undefined" -fno-sanitize-recover=all)
FUZZ_SAN=("-fsanitize=fuzzer,address,undefined" -fno-sanitize-recover=all)
NL=../../components/netbird_lite
PARSER_SRCS=("$SRC/nbl_ws.c" "$SRC/nbl_relaymsg.c" "$SRC/nbl_grpc.c" "$SRC/nbl_acl.c")
H2P_SRCS=("$SRC/nbl_h2p.c")
RELAY_SRCS=("$SRC/nbl_ws.c" "$SRC/nbl_relaymsg.c")
# nanopb-based network map decoding (generated code + vendored nanopb runtime)
PB=(-DPB_FIELD_32BIT=0 -I"$NL/proto_gen" -I"$NL/vendor/nanopb")
NANOPB=("$NL/vendor/nanopb/pb_decode.c" "$NL/vendor/nanopb/pb_common.c")
TARGETS=(fuzz_all fuzz_h2p fuzz_relay fuzz_acl fuzz_wire)

# UBSan reports with a stack trace; -fno-sanitize-recover above already makes them fatal.
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1${UBSAN_OPTIONS:+:$UBSAN_OPTIONS}"
# llvm-symbolizer asks the debuginfod servers listed in DEBUGINFOD_URLS (set by default on
# Ubuntu 24.04) for every library without local debug info. Without network access each
# lookup stalls: fuzzing dropped to a few executions per second and sanitizer reports hung.
# Symbolize from local files only.
unset DEBUGINFOD_URLS
# Hard limit for every fuzzer process on top of libFuzzer's own limits, so that a hanging
# process fails the run instead of stalling it.
WATCHDOG_SLACK=120

# Symbolized stack traces need llvm-symbolizer. Distributions often install it only under a
# versioned name (llvm-symbolizer-18) or inside the LLVM directory that clang reports.
find_symbolizer() {
  local c
  if command -v llvm-symbolizer >/dev/null 2>&1; then
    command -v llvm-symbolizer
    return 0
  fi
  if command -v "$CLANG" >/dev/null 2>&1; then
    c=$("$CLANG" -print-prog-name=llvm-symbolizer 2>/dev/null || true)
    if [[ $c == /* && -x $c ]]; then
      echo "$c"
      return 0
    fi
  fi
  for c in llvm-symbolizer-{22..11}; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}
if [ -z "${ASAN_SYMBOLIZER_PATH:-}" ] && sym=$(find_symbolizer); then
  export ASAN_SYMBOLIZER_PATH="$sym"
fi

# run_logged LOG CMD...: run CMD with all output in LOG; on failure show the end of the log
# and stop. No pipe is involved, so the exit status of CMD cannot get lost.
run_logged() {
  local log=$1 rc=0
  shift
  "$@" >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAILED (exit status $rc): $*" >&2
    if [ "$rc" -eq 124 ]; then
      echo "(stopped by the watchdog: the process hung)" >&2
    elif [ "$rc" -eq 137 ]; then
      echo "(killed by SIGKILL: watchdog or out of memory)" >&2
    fi
    tail -n 60 "$log" >&2
    echo "full log: $PWD/$log" >&2
    echo "crash inputs (if any): $PWD/$ART/" >&2
    exit 1
  fi
}

corpus_dir() {
  case $1 in
    fuzz_all) echo "$OUT/corpus" ;;
    fuzz_h2p) echo "$OUT/corpus_h2p" ;;
    fuzz_relay) echo "$OUT/corpus_relay" ;;
    fuzz_acl) echo "$OUT/corpus_acl" ;;
    fuzz_wire) echo "$OUT/corpus_wire" ;;
  esac
}

echo "== unit tests =="
"$CC" "${CFLAGS[@]}" -Werror "${SAN[@]}" test_units.c "${PARSER_SRCS[@]}" -o "$OUT/test_units"
"$OUT/test_units"
"$CC" "${CFLAGS[@]}" -Werror "${SAN[@]}" test_h2p.c "${H2P_SRCS[@]}" -o "$OUT/test_h2p"
"$OUT/test_h2p"
"$CC" "${CFLAGS[@]}" -Werror "${SAN[@]}" test_relay.c "${RELAY_SRCS[@]}" -o "$OUT/test_relay"
"$OUT/test_relay"
"$CC" "${CFLAGS[@]}" -Werror "${SAN[@]}" test_wire.c -o "$OUT/test_wire"
"$OUT/test_wire"
"$CC" "${CFLAGS[@]}" -Werror "${SAN[@]}" "${PB[@]}" test_rules.c "$SRC/nbl_netmap.c" "$SRC/nbl_acl.c" \
  "$NL/proto_gen/nbl_mgmt.pb.c" "${NANOPB[@]}" -o "$OUT/test_rules"
"$OUT/test_rules"

if ! command -v "$CLANG" >/dev/null 2>&1; then
  echo "error: '$CLANG' not found. The fuzz targets and the regression replay need clang" \
    "with libFuzzer (Debian/Ubuntu: apt install clang). Set CLANG to use another binary." >&2
  exit 1
fi

echo "== building fuzz targets =="
"$CLANG" "${CFLAGS[@]}" "${FUZZ_SAN[@]}" fuzz/fuzz_all.c "${PARSER_SRCS[@]}" -o "$OUT/fuzz_all"
"$CLANG" "${CFLAGS[@]}" "${FUZZ_SAN[@]}" fuzz/fuzz_h2p.c "${H2P_SRCS[@]}" -o "$OUT/fuzz_h2p"
"$CLANG" "${CFLAGS[@]}" "${FUZZ_SAN[@]}" fuzz/fuzz_relay.c "${RELAY_SRCS[@]}" -o "$OUT/fuzz_relay"
"$CLANG" "${CFLAGS[@]}" "${FUZZ_SAN[@]}" fuzz/fuzz_acl.c "$SRC/nbl_acl.c" -o "$OUT/fuzz_acl"
"$CLANG" "${CFLAGS[@]}" "${FUZZ_SAN[@]}" "${PB[@]}" fuzz/fuzz_wire.c "$SRC/nbl_netmap.c" \
  "$NL/proto_gen/nbl_mgmt.pb.c" "$NL/proto_gen/nbl_signal.pb.c" "${NANOPB[@]}" -o "$OUT/fuzz_wire"

shopt -s nullglob
REGRESS=(regress/*.bin)
if [ ${#REGRESS[@]} -gt 0 ]; then
  echo "== regression inputs: ${#REGRESS[@]} file(s), replayed through ${TARGETS[*]} =="
  for t in "${TARGETS[@]}"; do
    # libFuzzer executes each file argument once and exits non-zero if one of them crashes
    run_logged "$OUT/$t.regress.log" timeout -k 10 "$WATCHDOG_SLACK" \
      "$OUT/$t" -timeout=10 -artifact_prefix="$ART/$t-" "${REGRESS[@]}"
  done
else
  echo "== regression inputs: none found in tests/host/regress =="
fi

if [ "$FUZZ_SECS" -eq 0 ]; then
  echo "== fuzzing skipped (FUZZ_SECONDS=0) =="
else
  echo "== fuzzing: ${FUZZ_SECS} s per target =="
  # seed inputs: a valid relay transport message, WebSocket frames, a gRPC frame and
  # HTTP/2 frames (SETTINGS, HEADERS, DATA, PING)
  python3 - "$(corpus_dir fuzz_all)" "$(corpus_dir fuzz_h2p)" <<'PY'
import os
import sys

parsers, h2 = sys.argv[1], sys.argv[2]
os.makedirs(parsers, exist_ok=True)
os.makedirs(h2, exist_ok=True)


def put(d, name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


put(parsers, "seed_transport", bytes([1, 3]) + b"sha-" + bytes(32) + b"\x04\x00\x00\x00")
put(parsers, "seed_ws", bytes([0x82, 5]) + b"hello")
put(parsers, "seed_ws_frag", bytes([0x02, 3]) + b"abc" + bytes([0x80, 3]) + b"def")
put(parsers, "seed_grpc", bytes([0, 0, 0, 0, 5]) + b"hello")


def frame(t, f, i, p):
    return len(p).to_bytes(3, "big") + bytes([t, f]) + i.to_bytes(4, "big") + p


put(h2, "settings", frame(4, 0, 0, bytes([0, 4, 0, 0, 0, 0])))
put(h2, "headers", frame(1, 4, 1, bytes([0x88])))
put(h2, "data", frame(0, 1, 1, b"hello"))
put(h2, "ping", frame(6, 0, 0, b"12345678"))
PY
  mkdir -p "$(corpus_dir fuzz_relay)" "$(corpus_dir fuzz_acl)" "$(corpus_dir fuzz_wire)"
  cp -n "$(corpus_dir fuzz_all)"/seed_* "$(corpus_dir fuzz_relay)"/ 2>/dev/null || true
  # fuzz_acl: an outbound TCP SYN followed by the inbound SYN-ACK
  python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes([0,0,0,3,232]) + bytes([0x00,0x11,1,6,2,0,0, 0x01,0x11,1,6,0x12,0,0]))' \
    "$(corpus_dir fuzz_acl)/seed_syn_synack"
  # fuzz_wire: test_rules writes its encoded sync messages as seeds
  NBL_SEED_DIR="$(corpus_dir fuzz_wire)" "$OUT/test_rules" >/dev/null
  for t in "${TARGETS[@]}"; do
    log="$OUT/$t.log"
    run_logged "$log" timeout -k 10 "$((FUZZ_SECS + WATCHDOG_SLACK))" \
      "$OUT/$t" -max_total_time="$FUZZ_SECS" -timeout=10 \
      -print_final_stats=1 -artifact_prefix="$ART/$t-" "$(corpus_dir "$t")"
    runs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | tail -n 1)
    added=$(sed -n 's/^stat::new_units_added: *//p' "$log" | tail -n 1)
    echo "  $t: ${runs:-?} runs, ${added:-?} new corpus entries, no crash"
  done
fi

echo "all host tests passed"
