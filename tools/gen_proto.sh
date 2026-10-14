#!/usr/bin/env bash
# Regenerate the nanopb sources in components/netbird_lite/proto_gen/ from proto/*.proto.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/gen_proto.sh

Regenerates components/netbird_lite/proto_gen/*.pb.{c,h} from
components/netbird_lite/proto/*.proto with nanopb. Only needed after changing a .proto or
.options file; the generated files are committed.

The generator must have the same version as the nanopb runtime vendored in
components/netbird_lite/vendor/nanopb (checked by this script). Generator lookup order:
  1. $NANOPB_GENERATOR
  2. .venv-tools/bin/nanopb_generator in the repository
  3. nanopb_generator from PATH
Setup (from the repository root, version as in vendor/nanopb/pb.h):
  python3 -m venv .venv-tools
  .venv-tools/bin/pip install nanopb==0.4.9.1 protobuf grpcio-tools
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac
[ $# -eq 0 ] || { usage >&2; exit 2; }

cd "$(dirname "$0")/.."
ROOT=$PWD
if [ -n "${NANOPB_GENERATOR:-}" ]; then
  GEN=$NANOPB_GENERATOR
elif [ -x .venv-tools/bin/nanopb_generator ]; then
  GEN=$ROOT/.venv-tools/bin/nanopb_generator
elif command -v nanopb_generator >/dev/null 2>&1; then
  GEN=$(command -v nanopb_generator)
else
  echo "error: nanopb_generator not found (see tools/gen_proto.sh --help)" >&2
  exit 2
fi

# generated code and runtime must come from the same nanopb release
WANT=$(sed -n 's/^#define NANOPB_VERSION "\(.*\)"/\1/p' components/netbird_lite/vendor/nanopb/pb.h)
HAVE=$("$GEN" --version 2>/dev/null | head -n 1 || true)
if [ -z "$WANT" ] || [ "$HAVE" != "$WANT" ]; then
  echo "error: $GEN reports '${HAVE:-no version}', the vendored runtime is '${WANT:-unknown}'" >&2
  exit 2
fi

cd components/netbird_lite/proto
for p in nbl_mgmt nbl_signal; do
  "$GEN" -I . -f "$p.options" -D ../proto_gen "$p.proto"
done
ls -l ../proto_gen
