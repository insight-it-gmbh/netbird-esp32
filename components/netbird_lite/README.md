# netbird_lite

A NetBird client for ESP32 microcontrollers, packaged as an ESP-IDF component. The device joins a
[NetBird](https://netbird.io) network as a regular peer: other peers reach it under its NetBird IP,
NetBird access policies decide who may talk to it, and it needs no port forwarding, no public IP
and no VPN gateway in front of it.

> netbird-lite is an independent project. It is not affiliated with or endorsed by NetBird GmbH.

Documentation, measurements, test setup and protocol notes:
https://github.com/insight-it-gmbh/netbird-esp32

## Usage

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
```

Once connected, the device has a normal lwIP interface with its NetBird address, so sockets,
`esp_http_server` and MQTT work over it unchanged. `nbl_get_status()` reports the state, the
NetBird address, the peer count and relay/firewall counters. Options are under
`idf.py menuconfig` -> *netbird-lite*. A complete example app is in the repository
(`examples/basic`).

## Footprint

Measured with ESP-IDF 5.4.1 and `-Os`: 54 KB of flash on ESP32, 63 KB on ESP32-C6. While connected
about 65 KB of heap (both task stacks and two TLS connections included) plus 21 KB of static RAM.
On an ESP32-C6 over Wi-Fi: 46-50 ms ping and 143-146 kB/s for a 200 KB download through the relay.

## Limits

- All traffic goes through your NetBird relay: no direct peer-to-peer connections (no ICE, STUN
  or TURN), TLS relays only, and remote peers must use the same relay server.
- IPv4 only. No DNS, routes, exit nodes, SSH or lazy connections. Setup-key login only.
- Inbound filtering only. Policies with port ranges do not reach the device.
- At most `CONFIG_NBL_MAX_PEERS` remote peers (default 4, up to 8).

Tested against a self-hosted NetBird v0.80.0 on ESP32-C6 hardware and on ESP32 under QEMU.

## License

Apache-2.0, see `LICENSE`. If you distribute netbird-lite or a modified version of it, keep the
`NOTICE` file with it (section 4 of the license). Releases up to 0.2.0 were published under the
MIT license. Vendored third-party code and its licences are listed in `THIRD_PARTY_NOTICES.md`.

Copyright © 2026 Insight-IT GmbH, Berlin — https://www.insight-it.de
