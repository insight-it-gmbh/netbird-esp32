# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-14

First public release. Developed by Insight-IT GmbH.

### Features

- NetBird peer on ESP32 as an ESP-IDF component: registration with a setup key and a persistent
  WireGuard identity in NVS, management `Login`/`Sync`, signal offer/answer, relay transport over
  WebSocket/TLS, WireGuard via a patched wireguard-lwip, lwIP interface with the NetBird address.
- Own minimal HTTP/2 client with HPACK and Huffman decoding; nghttp2 stays selectable as a
  reference backend (`CONFIG_NBL_H2_NGHTTP2`, opt-in dependency).
- Stateful inbound firewall from the NetBird access policies: connection tracking for TCP, UDP
  and ICMP echo, `DROP` rules before `ACCEPT` rules, destination check, fragment handling,
  fail-closed rule parsing.
- Self-healing: reconnects with backoff and jitter after management, signal or relay outages,
  re-registers when the peer was deleted on the server, applies policy changes live.
- Reports `0.44.0+netbird-lite.0.2.0` so that NetBird servers and peers switch on exactly the
  features this client implements (see `docs/PROTOCOL-NOTES.md`).
- Example application with `/`, `/status`, `/echo`, `/blob`, `/fetch` and a filtered test port.
- Host test suite: unit tests under ASan/UBSan and five libFuzzer targets for every parser that
  sees network data; QEMU and hardware end-to-end and soak tests; CI on GitHub Actions.

### Performance (ESP32-C6 over a NetBird relay, measured)

- Ping 168 -> 46-50 ms, 200 KB download 55 -> 143-146 kB/s, free heap while connected
  172 -> 229 KB compared with the first internal version on ESP-IDF defaults.

### Security fixes found by review and fuzzing before the release

- No traffic for NetBird addresses leaves unencrypted through the default route while no
  WireGuard session exists (the interface link stays up).
- A hostile relay can no longer overflow the relay task stack with control frames, and a
  hostile signal server can no longer hang the control task with oversized length fields.
- One oversized field in a network map no longer makes the device discard the whole map.
- The device key is never replaced silently after an NVS read error; optional entropy source for
  key generation on boards without Wi-Fi/Bluetooth (`CONFIG_NBL_KEYGEN_ENTROPY_SOURCE`).

[0.2.0]: https://github.com/insight-it-gmbh/netbird-esp32/releases/tag/v0.2.0
