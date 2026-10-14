#!/usr/bin/env bash
# Build the example application (examples/basic) with ESP-IDF.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/build.sh [MODE]

Builds examples/basic with ESP-IDF. MODE is one of:
  qemu      ESP32 for QEMU with OpenCores Ethernet (default)
  esp32s3   ESP32-S3 with Wi-Fi
  esp32c6   ESP32-C6 with Wi-Fi

Your own settings (management URL, setup key, Wi-Fi credentials) go into gitignored files
in examples/basic/, using the same syntax as sdkconfig.defaults:
  sdkconfig.defaults.qemu.local   read in mode qemu
  sdkconfig.defaults.local        read in modes esp32s3 and esp32c6

Each mode builds in examples/basic/build-<mode> with its own config file
examples/basic/sdkconfig.build-<mode>. ESP-IDF applies the defaults files only when that
config file is created: delete it to pick up changed defaults.

ESP-IDF is taken from $IDF_PATH/export.sh if IDF_PATH is set, otherwise from
~/esp/esp-idf/export.sh. The build runs in a clean environment (env -i) so that an active
Python virtualenv cannot interfere with ESP-IDF's own Python environment. Passed through:
IDF_PATH, IDF_TOOLS_PATH, IDF_CCACHE_ENABLE, IDF_COMPONENT_*, IDF_GITHUB_ASSETS and the
proxy variables. Developed with ESP-IDF v5.4.1.
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
# and its component manager may need (tool location, ccache, registry mirrors, proxies).
idf_env() {
  IDF_ENV=(env -i "HOME=$HOME" "PATH=/usr/local/bin:/usr/bin:/bin" "LANG=C.UTF-8" "TERM=${TERM:-dumb}")
  local v
  while IFS= read -r v; do
    case "$v" in
      IDF_PATH | IDF_TOOLS_PATH | IDF_CCACHE_ENABLE | IDF_COMPONENT_* | IDF_GITHUB_ASSETS | \
        http_proxy | https_proxy | no_proxy | HTTP_PROXY | HTTPS_PROXY | NO_PROXY)
        IDF_ENV+=("$v=${!v}")
        ;;
    esac
  done < <(compgen -e)
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac
[ $# -le 1 ] || { usage >&2; exit 2; }
MODE="${1:-qemu}"

cd "$(dirname "$0")/../examples/basic"
case "$MODE" in
  qemu)
    TARGET=esp32
    DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.qemu"
    BUILD=build-qemu
    if [ -f sdkconfig.defaults.qemu.local ]; then
      DEFAULTS="$DEFAULTS;sdkconfig.defaults.qemu.local"
    fi
    ;;
  esp32s3 | esp32c6)
    TARGET=$MODE
    DEFAULTS="sdkconfig.defaults"
    BUILD=build-$MODE
    if [ -f sdkconfig.defaults.local ]; then
      DEFAULTS="$DEFAULTS;sdkconfig.defaults.local"
    fi
    ;;
  *)
    echo "error: unknown mode '$MODE'" >&2
    usage >&2
    exit 2
    ;;
esac

IDF_EXPORT=$(find_idf_export)
idf_env
# shellcheck disable=SC2016 # the inner script expands its variables itself
"${IDF_ENV[@]}" IDF_EXPORT="$IDF_EXPORT" TARGET="$TARGET" DEFAULTS="$DEFAULTS" BUILD="$BUILD" bash -c '
  # export.sh is chatty and reports its own errors on stdout: show its output only on failure
  log=$(mktemp)
  if ! . "$IDF_EXPORT" >"$log" 2>&1; then
    cat "$log" >&2
    rm -f "$log"
    echo "error: sourcing $IDF_EXPORT failed" >&2
    exit 1
  fi
  rm -f "$log"
  set -eo pipefail
  command -v idf.py >/dev/null || { echo "error: idf.py not found after sourcing $IDF_EXPORT" >&2; exit 1; }
  export SDKCONFIG_DEFAULTS="$DEFAULTS"
  if [ ! -f "sdkconfig.$BUILD" ]; then
    rm -rf "$BUILD"
    idf.py -B "$BUILD" -DSDKCONFIG="sdkconfig.$BUILD" set-target "$TARGET"
  fi
  nice -n 10 idf.py -B "$BUILD" -DSDKCONFIG="sdkconfig.$BUILD" build
'
