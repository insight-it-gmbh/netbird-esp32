# Contributing

Thanks for helping. A few rules keep this small client small and safe.

## Before you send a change

- Run `tests/host/run.sh` (unit tests under ASan/UBSan, regression inputs, short fuzzing). It needs
  clang with libFuzzer; on Debian/Ubuntu `apt install clang libclang-rt-18-dev`.
- Build the example for at least one target: `tools/build.sh esp32c6` (or `qemu`).
- If you can, run `tools/e2e_test.sh <device-ip>` against a device in a test network
  (`tools/nb_testenv.py` creates one) and say in the pull request what you tested on.

## Hard constraints

- **Everything that parses data from the network is a pure module** (no ESP-IDF, FreeRTOS or lwIP
  headers) with unit tests in `tests/host/` and a libFuzzer target in `tests/host/fuzz/`. Inputs that
  once crashed a fuzzer go into `tests/host/regress/`.
- **Fail closed.** Firewall rules or protocol fields that do not parse are skipped, never widened to
  "any".
- **Bounded memory.** Every buffer that a server or peer can grow has a hard limit; exceeding it drops
  the message or closes the connection, it never grows the heap without bound.
- **Wire compatibility.** Message names, field names and field numbers in `proto/` match upstream
  NetBird. Do not renumber; add fields only as they exist upstream.
- **Vendored code** (`components/netbird_lite/vendor/`) stays as close to upstream as possible.
  Every change to wireguard-lwip must be reflected in `NBL-PATCH.diff` (the exact diff against the
  upstream commit named in its header).
- No new runtime dependencies without discussion. C11, 4-space indentation, English comments,
  ASCII only.

## Reporting bugs

Please include the ESP-IDF version, the chip, the NetBird server version, and the log of the
`nbl`, `nbl_relay` and `nbl_h2` tags. Security issues: please use GitHub's private
*Report a vulnerability* function instead of a public issue.
