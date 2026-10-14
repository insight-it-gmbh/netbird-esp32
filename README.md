# netbird-lite

**A NetBird client for ESP32 microcontrollers.**

[![CI](https://github.com/insight-it-gmbh/netbird-esp32/actions/workflows/ci.yml/badge.svg)](https://github.com/insight-it-gmbh/netbird-esp32/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![ESP-IDF 5.x](https://img.shields.io/badge/ESP--IDF-5.x-E7352C.svg)](https://github.com/espressif/esp-idf)
[![Made by Insight-IT GmbH](https://img.shields.io/badge/Made%20by-Insight--IT%20GmbH-9DCD5A.svg)](https://www.insight-it.de)

netbird-lite puts an ESP32 into a [NetBird](https://netbird.io) network as a regular peer. Other
peers reach it under its NetBird IP, NetBird access policies decide who may talk to it, and it
needs no port forwarding, no public IP and no VPN gateway in front of it. It is an ESP-IDF
component written in C: 54 KB of flash on ESP32 and 63 KB on ESP32-C6, and while connected
about 65 KB of heap (both task stacks and two TLS connections included) plus 21 KB of static RAM.

> netbird-lite is an independent project. It is not affiliated with or endorsed by NetBird GmbH.

## Why this exists

The official NetBird client is written in Go. On Linux (x86-64, v0.80.0) its binary is 41 MB and
the running daemon uses about 50 MB of RAM; an ESP32 has about 0.5 MB. Running NetBird on an
ESP32 has been a long-standing community request
([netbirdio/netbird#4317](https://github.com/netbirdio/netbird/issues/4317)). netbird-lite
implements the part of the protocol a small device needs, and nothing else.

We built it because we wanted small devices in our own NetBird network, and released it under
the Apache-2.0 license in case it is useful to you too.

## What it does

| Part | Implementation | Purpose |
|---|---|---|
| Management | gRPC over HTTP/2 over TLS, payloads sealed with NaCl box | `GetServerKey`, `Login` with a setup key, `Sync` stream (network map, peers, firewall rules, relay tokens) |
| Signal | gRPC, NaCl box | offer/answer with remote peers (`ConnectStream` to receive, unary `Send` to send) |
| HTTP/2 | own minimal client (`nbl_h2p`, HPACK + Huffman, ~15 KB); nghttp2 selectable | RFC 9113 / RFC 7541 subset needed for gRPC |
| Relay | WebSocket (RFC 6455) over TLS, NetBird relay protocol | carries the WireGuard packets; authenticated with the HMAC token from management |
| WireGuard | [wireguard-lwip](https://github.com/smartalock/wireguard-lwip), small patch | lwIP network interface with the NetBird IP; transport is the relay instead of UDP |
| Firewall | inbound filter at the interface (`nbl_acl`) | enforces the access policies from the network map (peer IP, protocol, port / port range) |
| Protobuf | nanopb with only the fields used | field numbers identical to upstream |

Once connected, the device has a normal lwIP interface with its NetBird address. Sockets,
`esp_http_server`, MQTT clients and everything else work over it unchanged.

Behaviour that is tested end to end (see [Testing](#testing)): registration with a setup key and
a persistent identity, ICMP, TCP and HTTP from other peers, 200 KB transfers with checksum,
ports outside the policy stay closed, policy changes apply live, the device re-registers by itself
when its peer is deleted on the server, and it recovers on its own when the management, signal or
relay connection drops.

## What it deliberately does not do

- **No direct (peer-to-peer) connections.** No ICE, STUN or TURN: all traffic goes through your
  NetBird relay, like the official client with *Force relay connection*. Relay only sees WireGuard
  ciphertext.
- Only TLS relays (`rels://`), no QUIC relay. Remote peers must use the same relay server.
- IPv4 only. No DNS, routes or exit nodes, SSH, Rosenpass, lazy connections, posture checks.
- Setup-key login only (no SSO / device flow).
- Inbound filtering only; outbound traffic is not filtered.
- At most `CONFIG_NBL_MAX_PEERS` remote peers (default 4); further peers in the network map are
  ignored and logged.

## Measured performance

ESP32-C6 (Wi-Fi, no PSRAM) and ESP32 under QEMU, ESP-IDF 5.4.1, `-Os`, against a self-hosted
NetBird v0.80.0. Ping and transfers from another peer through the relay; the plain network round
trip from that peer to the relay server is 17 ms.

| | ESP32-C6, Wi-Fi | ESP32 in QEMU, Ethernet |
|---|---|---|
| Ping through the relay (3 x 20 pings) | 46-50 ms | 38 ms |
| 200 KB HTTP download from the device, SHA-256 checked | 143-146 kB/s | 144-192 kB/s |
| Free heap while connected / lowest during transfers | 229 KB / 164 KB | 172 KB / 109 KB |
| Firmware image of the example app | 943 KB | 545 KB |

The first internal version, on plain ESP-IDF defaults, measured 168 ms and 55 kB/s on the same
ESP32-C6 with 172 KB of free heap. What changed is listed under [Tuning](#tuning).

Most of the latency is the relay path (twice the round trip to the relay server). Wi-Fi power
save adds up to ~100 ms on the device side; the example turns it off with
`CONFIG_EXAMPLE_WIFI_PS_NONE`. Throughput is limited by the TCP window over the relay round trip,
see [Tuning](#tuning).

## Quick start

Requirements: ESP-IDF 5.x (developed with 5.4.1), a NetBird management server (tested:
self-hosted v0.80.0), a setup key, and a policy that lets your other peers reach the device.

```bash
git clone https://github.com/insight-it-gmbh/netbird-esp32.git
cd netbird-esp32/examples/basic
cat > sdkconfig.defaults.local <<'EOF'
CONFIG_EXAMPLE_NB_MGMT_URL="https://netbird.example.com"
CONFIG_EXAMPLE_NB_SETUP_KEY="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
CONFIG_EXAMPLE_NB_HOSTNAME="esp32-demo"
CONFIG_EXAMPLE_CONNECT_WIFI=y
CONFIG_EXAMPLE_WIFI_SSID="your-ssid"
CONFIG_EXAMPLE_WIFI_PASSWORD="your-password"
EOF
cd ../..
tools/build.sh esp32c6          # or esp32s3, or qemu
idf.py -C examples/basic -B examples/basic/build-esp32c6 -p /dev/ttyUSB0 flash monitor
```

`sdkconfig.defaults.local` is git-ignored. After a few seconds the peer shows up in the NetBird
dashboard; then, from another peer:

```console
$ curl http://<device-netbird-ip>/
hello from ESP32 over NetBird (100.92.10.20/16), free heap: 231824 bytes
$ curl http://<device-netbird-ip>/status
```

## Using the component

Add it to your project with the ESP-IDF component manager (`main/idf_component.yml`):

```yaml
dependencies:
  netbird_lite:
    git: https://github.com/insight-it-gmbh/netbird-esp32.git
    path: components/netbird_lite
```

or copy `components/netbird_lite` into your project's `components/` directory. Then:

```c
#include "netbird_lite.h"

ESP_ERROR_CHECK(nvs_flash_init());          /* the WireGuard key is stored in NVS */
/* bring up Wi-Fi or Ethernet and wait for an IP address */
nbl_config_t cfg = {
    .management_url = "https://netbird.example.com",
    .setup_key      = "XXXXXXXX-...",          /* only needed for the first registration */
    .hostname       = "esp32-demo",            /* NULL: "esp32-<MAC>" */
};
ESP_ERROR_CHECK(nbl_start(&cfg));            /* starts the tasks and returns immediately */

nbl_status_t st;
nbl_get_status(&st);                         /* state, ip, peers_up, relay_up, counters ... */
```

Kconfig (`idf.py menuconfig` -> *netbird-lite*):

| Option | Default | Meaning |
|---|---|---|
| `NBL_H2_LITE` / `NBL_H2_NGHTTP2` | lite | HTTP/2 implementation. nghttp2 needs `idf.py add-dependency "espressif/nghttp^1.65.0"` and costs about 70 KB more flash |
| `NBL_MAX_PEERS` | 4 | remote peers (1-8), about 1.1 KB of RAM each |
| `NBL_MAX_RULES` | 32 | inbound firewall rules |
| `NBL_ACL_ENFORCE` | y | enforce the NetBird access policies on inbound traffic |
| `NBL_CT_ENTRIES` | 16 | connection tracking entries (16 bytes each) |
| `NBL_MTU` | 1280 | WireGuard MTU, unless management sends one |
| `NBL_SNTP`, `NBL_SNTP_SERVER` | y, pool.ntp.org | set the clock if nobody else does (TLS and WireGuard need it) |
| `NBL_KEYGEN_ENTROPY_SOURCE` | n | entropy source for the first key generation on Ethernet-only boards, see [Security](#security) |
| `NBL_CTRL_STACK`, `NBL_RELAY_STACK` | 10240, 6144 | task stacks; measured peaks about 6.3 KB and 4 KB |

`nbl_get_status()` returns the state, the NetBird address, the WireGuard public key, the peer
count and relay/firewall counters; `nbl_forget()` erases the stored identity.

## Tuning

The client itself needs no tuning, but the ESP-IDF defaults are sized for minimal memory, not
for a tunnel with a 40-100 ms round trip. The example ships with these settings
(`examples/basic/sdkconfig.defaults`); every number below was measured on the ESP32-C6:

| Configuration (ESP32-C6, Wi-Fi, one relay) | Ping | 200 KB download | Free heap |
|---|---|---|---|
| first internal version, ESP-IDF defaults | 168 ms | 55 kB/s | 172 KB |
| + relay task woken for every outgoing packet (in the client) | 107 ms | 81 kB/s | 171 KB |
| + Wi-Fi power save off, TCP window 16 segments | 48 ms | 150 kB/s | 171 KB |
| + TLS buffers only while in use, smaller lwIP thread stack | 48 ms | 146 kB/s | 237 KB |
| release 0.2.0 (all fixes, example defaults) | 46-50 ms | 143-146 kB/s | 229 KB |

The settings, all in the example's `sdkconfig.defaults`:

- `CONFIG_LWIP_TCP_SND_BUF_DEFAULT=23040`, `CONFIG_LWIP_TCP_WND_DEFAULT=23040`,
  `CONFIG_LWIP_TCP_RECVMBOX_SIZE=16`: a window of 16 instead of 4 segments. The memory is only used
  while data is in flight (the lowest free heap during a transfer dropped by about 40 KB).
- `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y`, `CONFIG_MBEDTLS_DYNAMIC_FREE_CONFIG_DATA=y`,
  `CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=n`: 60 KB more free heap. No throughput cost on the
  ESP32-C6; under QEMU emulation it halves throughput, so leave it off for QEMU benchmarks.
- `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE=4096`: WireGuard runs in the lwIP thread; measured peak 1.4 KB.
- `CONFIG_EXAMPLE_WIFI_PS_NONE=y` (example option): Wi-Fi modem sleep delays every received
  packet by up to a beacon interval. Turn it off for battery-powered devices.

## Testing

| Level | What | How |
|---|---|---|
| Host | unit tests for the parsers (WebSocket, relay messages, gRPC framing, ACL, HTTP/2 + HPACK incl. RFC 7541 test vectors), built with ASan + UBSan | `tests/host/run.sh` |
| Host | libFuzzer targets for every parser that sees server data, plus regression inputs | `tests/host/run.sh 60` (seconds per target) |
| QEMU | ESP32 with emulated Ethernet against a real NetBird server | `tools/build.sh qemu && tools/qemu_run.sh 300` |
| End to end | ping, HTTP, echo, 200 KB transfer with SHA-256, closed port really closed, ACL counters | `tools/e2e_test.sh <device-ip>` |
| Soak | ping + checksummed transfers over time | `tools/soak.sh <device-ip> <minutes>` |
| Hardware | the same end-to-end and soak tests on an ESP32-C6 | — |

`tools/nb_testenv.py` creates a matching test setup in a NetBird account through the REST API
(group, policies, reusable setup key) and removes it again.

## Security

- **Firewall on by default** (`CONFIG_NBL_ACL_ENFORCE`). Without it the device accepts anything
  from every peer in its network map, whatever the policy says. Only inbound traffic is filtered.
- **The WireGuard private key is stored in NVS in plain text.** For production devices enable
  flash encryption and NVS encryption.
- **Random numbers:** the key is generated on first start with `esp_fill_random()`. ESP-IDF only
  guarantees true randomness while Wi-Fi/Bluetooth runs or an entropy source is enabled. On
  Ethernet-only boards enable `CONFIG_NBL_KEYGEN_ENTROPY_SOURCE` (see Kconfig help) or provision
  the device on Wi-Fi.
- **Setup keys** compiled into firmware can be extracted from it. Use one-off keys bound to a
  group, or pass the key at run time. After a successful registration the key is no longer used.
- TLS certificates are verified against the ESP-IDF certificate bundle (the example uses the
  *common CAs* subset; switch to the full bundle if your server's CA is missing). This needs a
  correct clock; SNTP is built in.
- The relay only sees WireGuard ciphertext, but its operator sees metadata (who talks to whom,
  how much).

Please report security issues privately through GitHub's *Report a vulnerability* button.

## How it works

```
 ESP32                                                     NetBird server(s)
 ┌──────────────────────────────────────────┐
 │ your app (sockets, HTTP server, MQTT ...) │
 ├──────────────────────────────────────────┤
 │ lwIP ── netif "nb" (NetBird IP) ── ACL    │
 │          │                                │
 │       WireGuard (wireguard-lwip)          │
 │          │ encrypted packets              │      ┌──────────┐
 │       relay task ── WebSocket/TLS ────────┼─────►│  relay   │◄── other peers
 │                                           │      └──────────┘
 │       control task ── gRPC/HTTP2/TLS ─────┼─────►┌──────────┐
 │         (login, sync, signal offers)      │      │management│
 └──────────────────────────────────────────┘      │ + signal │
                                                    └──────────┘
```

Two tasks: the control task owns the management and signal connections (they share one HTTP/2
connection when both use the same host), the relay task owns the relay connection. WireGuard runs
in the lwIP thread. The protocol details that are not documented upstream, and the traps we hit
while implementing them, are in [docs/PROTOCOL-NOTES.md](docs/PROTOCOL-NOTES.md).

## Contributing

Issues and pull requests are welcome. Please run `tests/host/run.sh` before sending changes, keep
new parsers host-testable (no ESP-IDF headers) and add a fuzz target for anything that parses
data from the network. See [CONTRIBUTING.md](CONTRIBUTING.md).

## About the authors

<a href="https://www.insight-it.de">
  <img src=".assets/brand.png" alt="Insight-IT GmbH" height="60">
</a>

**[Insight-IT GmbH](https://www.insight-it.de)** is an IT service provider in Berlin, Germany.
For over 20 years serving companies, public clients, and government organizations.

Built and maintained by **[Dominic Ballenthin](https://github.com/subbie5000)**.

[![Website](https://img.shields.io/badge/Website-insight--it.de-9DCD5A?style=flat-square&logo=firefoxbrowser&logoColor=white)](https://www.insight-it.de)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Insight--IT-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/insight-it-gmbh-06b979171/)
[![GitHub](https://img.shields.io/badge/GitHub-insight--it--gmbh-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/insight-it-gmbh)

## License

Apache-2.0, see [LICENSE](LICENSE). If you distribute netbird-lite or a modified version of it, keep
the [NOTICE](NOTICE) file with it, as section 4 of the license requires. Releases up to 0.2.0 were
published under the MIT license. Third-party components and their licences are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

NetBird is developed by NetBird GmbH. WireGuard and the WireGuard logo are registered trademarks
of Jason A. Donenfeld. This project is not affiliated with either.

Copyright © 2026 Insight-IT GmbH, Berlin — Dominic Ballenthin.
