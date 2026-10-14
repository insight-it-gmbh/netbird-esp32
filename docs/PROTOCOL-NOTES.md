# Protocol notes

How netbird-lite talks to NetBird, and the pitfalls we ran into while building it. Most of
this is not documented upstream; it was derived from the NetBird v0.80.0 sources
(`shared/management`, `shared/signal`, `shared/relay`, `client/internal/peer`) and from
debugging against a self-hosted NetBird server with the official Linux client as the
remote peer.

## Connection sequence

### 1. Clock

TLS certificate validation and WireGuard handshake timestamps both need a valid wall
clock, so the control task waits for SNTP before it connects.

### 2. Management (gRPC over HTTP/2, `https://host:443`, ALPN `h2`)

- `GetServerKey` returns the server's WireGuard public key (Base64).
- `Login`: `LoginRequest{setupKey, meta}` is sealed in a NaCl box (sender: our WireGuard
  key, recipient: the server key) and sent as `EncryptedMessage{wgPubKey=1, body=2}`.
  Send the setup key only until the first successful login; afterwards the WireGuard key
  alone identifies the peer.
- Login answers: gRPC status 7 (PermissionDenied) without a setup key means "peer not
  registered" (send the setup key); 5 (NotFound) with a setup key means the key is invalid,
  expired, revoked or used up. 3 (InvalidArgument) also comes back when the server cannot
  decrypt the request, for example after its key changed: retry, do not forget the
  registration.
- `Sync` is a server stream. The first response carries `NetbirdConfig` (signal URI,
  relay URL and relay token) and the `NetworkMap` (own overlay address, remote peers,
  firewall rules). Later responses deliver every change as a complete new map with a
  higher `Serial`.
- Only a client that sends **no** `syncMessageVersion` gets the plain `NetworkMap` format;
  otherwise the server may answer with the component-based variant.

### 3. Signal (gRPC)

- If the signal URI has the same host and port as management, the existing HTTP/2
  connection is reused. Otherwise a separate connection is opened in a short-lived helper
  task, because the TLS handshake takes longer than the management server's keepalive
  allows (it pings after 5 s of silence and closes the connection 2 s later).
- `ConnectStream` with the request header `x-wiretrustee-peer-id: <own public key>` is
  **receive-only**: the server never reads from this stream. The response header
  `x-wiretrustee-peer-registered` confirms the registration.
- Messages are sent with **separate unary `Send` calls**:
  `EncryptedMessage{key=2, remoteKey=3, body=4}`.
- `body` is a NaCl box between the two peers containing
  `Body{type, payload, wgListenPort, netBirdVersion, relayServerAddress=8}`.
- Without ICE, `payload` is `":"` (empty `ufrag:pwd` credentials). The Go client
  recognises this and uses the relay only.
- `relayServerAddress` must be the **instance URL from the relay's auth response**.
  Without it the remote peer never opens a relay path. Remote peers must be connected to
  the same relay instance; netbird-lite keeps a single relay connection.
- Offers can arrive before our relay connection is up. Answer them later, as soon as the
  relay is connected.

### 4. Relay (`rels://host:443` -> `wss://host:443/relay`, binary WebSocket messages)

- Auth: `[1][6][0x2112A442][peer ID, 36 bytes][token]`
  - `peer ID = "sha-" + SHA-256(the Base64 public key as text)`
  - `token = [1 = HMAC-SHA256][signature, 32 bytes][payload as text]`, taken from
    `RelayConfig{tokenPayload, tokenSignature}` in the management config.
- Auth response: `[1][7][instance URL]`.
- Data: `[1][3][peer ID][WireGuard packet]`. Outgoing messages carry the destination ID,
  incoming ones the sender's ID.
- The server sends a health check (`[1][5]`) every 25 s that must be answered, otherwise it
  closes the connection. Like the Go client, netbird-lite gives up on a connection that has
  been silent for 35 s (25 s + 10 s grace); without that check a relay host that vanishes
  without a TCP reset is only noticed after many minutes.
- On a graceful stop or reconfiguration the client sends the close message `[1][4]`.

### 5. WireGuard

One wireguard-lwip peer per remote peer. Each peer gets a tag (table index + 1) in place
of its UDP port; outgoing and incoming packets are routed by this tag to and from the
relay instead of through sockets.

### 6. Reported version and the server's feature gates

The management server and the official clients switch features on the peer's reported
NetBird version (hashicorp/go-version). netbird-lite reports
**`0.44.0+netbird-lite.<version>`**: build metadata keeps the string honest and is ignored
in comparisons.

| Gate (NetBird v0.80.0) | Needs | Effect for netbird-lite |
|---|---|---|
| No duplicate deprecated `remotePeers` list | >= 0.29.3 | not sent (saves memory) |
| Remote peers use lazy connections to us | >= 0.45.0 | off: remote peers keep a permanent connection; netbird-lite implements neither lazy connections nor `GO_IDLE` |
| Port ranges in firewall rules | >= 0.48.0 | off: rules with a real port range are **not delivered**, so that traffic stays blocked |
| Native SSH rules | >= 0.60.0 | off |
| Remote jobs | >= 0.64.0 | off |

A pre-release suffix such as `0.1.0-nbl` fails **every** `>=` constraint in go-version,
whatever the numbers. Strings starting with `development`, `dev-` or `ci-` pass every gate.

## Pitfalls

All of these actually happened.

### Signal

- **Do not send on `ConnectStream`.** Messages written to it disappear silently: the
  stream stays open and no error is reported.

### Relay and WebSocket

- **Wake the relay task when a packet is queued.** The relay task blocks in `select()` on
  the TLS socket. With a 50 ms timeout and no wake-up, every reply (ICMP echo, TCP ACK)
  waited for the timeout: 95 ms ping in QEMU and 168 ms on an ESP32-C6. An `eventfd` in the
  `select()` set brought this down to 39 ms and 48 ms. netbird-lite registers the eventfd
  VFS itself; an application that also uses eventfd must register it **before**
  `nbl_start()`.
- **Do not recurse per WebSocket frame.** A loop that calls itself for every PING, PONG or
  fragment overflows the task stack with a few hundred empty frames from a hostile server.
- Reset the WebSocket reassembly state for every new connection; a fragment left over from
  a dropped connection otherwise breaks every later handshake.

### HTTP/2 and gRPC

- See [HTTP/2 client](#http2-client-nbl_h2p) below.

### Firewall

- **The inbound filter must be stateful.** NetBird delivers `OUT` rules to the side that
  opens a connection and expects connection tracking. A stateless filter drops the
  SYN-ACK of every connection the device opens itself (it arrives on an ephemeral port).
  netbird-lite tracks outbound TCP, UDP and ICMP echo flows in a small LRU table
  (`CONFIG_NBL_CT_ENTRIES`) and lets their replies through.
- Order of evaluation: destination must be our own NetBird address, then tracked replies,
  then `DROP` rules, then `ACCEPT` rules, else drop. Malformed rules are skipped, never
  widened to "any". Trailing IP fragments inherit the verdict of the first fragment.

### ESP-IDF, lwIP and wireguard-lwip

- **Never take the WireGuard netif's link down.** wireguard-lwip clears the link flag while
  no peer has a session. lwIP's `ip4_route()` skips netifs without link, so traffic for
  NetBird addresses then left **unencrypted through the default route** (before the first
  handshake and whenever the keys expired). The vendored copy keeps the link up; without a
  session wireguard-lwip drops the packet.
- **Never abandon a call queued to the TCP/IP thread.** A version that stopped waiting after
  3 s returned while the queued function still pointed at the caller's stack frame
  (use-after-free). Calls now block like lwIP's own netconn API (`tcpip_callback_wait()`).
- **ESP-IDF interprets `netif->state` as an `esp_netif_t`** when no client data slot is
  configured (`LWIP_ESP_NETIF_DATA=0`). Every lwIP address callback (`netif_set_addr`,
  `netif_set_ipaddr`, ...) then crashes on a netif that ESP-IDF does not own
  (LoadProhibited in the DHCP callback). Fix: create the interface with
  `netif_add_noaddr()` and write the address fields directly.
- **wireguard-lwip calls `ip_input()` directly** instead of `netif->input`, which bypasses
  an inbound filter installed on the netif. `vendor/wireguard-lwip/NBL-PATCH.diff` routes
  decrypted packets through `netif->input`, where the ACL runs.
- **wireguard-lwip assumes IPv4-only lwIP.** With IPv6 enabled, `ip_addr_t` and
  `ip4_addr_t` are different types (see `NBL-PATCH.diff` and `ip_2_ip4()`).

### nanopb

- **One oversized field rejects the whole message.** With fixed `max_count`/`max_size`
  limits, a third relay URL, a routing peer with several networks in `allowedIps` or a
  long prefix string made nanopb discard the entire `SyncResponse`, so the device never got
  a network map. Every server-controlled string or list is now decoded through a callback
  that keeps what the client needs and skips the rest.

### Clock

- Without a valid time, TLS certificate validation fails on the ASN.1 validity dates.
  This is why the control task waits for SNTP.

### Device identity and setup keys

- **Two devices with the same key displace each other.** The management server closes the
  older `Sync` stream and the relay the older connection. This looks like a protocol
  error. It happens easily with two QEMU instances started from the same flash image,
  which is why `tools/qemu_run.sh` refuses to start a second instance.
- The QEMU flash image `flash_persist-*.bin` lives outside the build directory and keeps
  the NVS partition (and with it the identity) across rebuilds. This only holds while the
  partition table stays the same; after a layout change the device registers as a new
  peer, which is harmless with a reusable setup key.
- **One-off setup keys are consumed by the first login.** A device without a stored key
  (empty NVS) needs a new setup key, even if a peer with the same hostname already exists.
- When the peer is deleted on the server, the next login is answered with "not
  registered"; a device that still has its setup key registers again by itself.

## HTTP/2 client (nbl_h2p)

netbird-lite uses its own minimal HTTP/2 client by default; nghttp2 remains selectable as a
reference backend (`CONFIG_NBL_H2_NGHTTP2`).

- **Stream IDs grow without bound** (1, 3, 5, ...). An early version stored streams at
  `slot = (id / 2) % cap` and recomputed the ID from the slot. From the ninth stream on,
  responses became invisible: DATA was dropped silently, which only showed up on RPCs with
  a response body. Streams are now stored with open addressing and the explicit ID in the
  entry; `tests/host/test_h2p.c` has a regression test.
- **Queue frames atomically.** A frame header queued without its payload corrupts the
  connection for good. Frames are queued whole or not at all, DATA is moved from per-stream
  buffers into the send queue as flow control allows, and the input side applies
  back-pressure when the queue is full.
- **Streams end on the server's END_STREAM.** grpc-go happens to send `RST_STREAM` after the
  trailers, but relying on it left a signal stream silently dead when it did not arrive.
- **HPACK:** static table plus Huffman decoding. The dynamic table is disabled
  (`SETTINGS_HEADER_TABLE_SIZE = 0`), so the server cannot refer to dynamic table entries;
  literals flagged "with incremental indexing" are decoded and not stored. Header blocks are
  decoded field by field as CONTINUATION frames arrive; fields too large for the client
  (long cookies or policy headers added by a proxy) are skipped instead of failing.
- Requests use static table references and literals without indexing, never Huffman
  coding (allowed by RFC 7541).
- **Flow control:** we announce `INITIAL_WINDOW_SIZE` of about 1 MB and enlarge the
  connection window by the same amount at start-up. Received data is credited back with
  one `WINDOW_UPDATE` per input batch, including padding and DATA for streams that are
  already closed (otherwise the connection window shrinks until `Sync` stalls).
- The first frame from the server must be `SETTINGS`, and ALPN must have negotiated `h2`;
  otherwise the connection is refused with a clear log message.
- Unary calls have a deadline (`nbl_h2_set_deadline()`), so a server that never answers a
  signal `Send` cannot hold stream slots forever.

## NetBird REST API (test setup)

- **One rule per policy.** When a policy is created, NetBird (v0.80) gives every rule the
  policy's own ID, and the rule ID is the primary key, so a policy created with two rules
  keeps only one. `tools/nb_testenv.py` therefore creates one policy per protocol (ICMP,
  TCP 80).

## Debugging

- HTTP/2 frame trace (nghttp2 backend only): add `NBL_H2_TRACE=1` to
  `target_compile_definitions` in `components/netbird_lite/CMakeLists.txt`. Every sent and
  received frame is logged with type, stream and length.
- On the remote Linux peer, `netbird debug log level debug` shows `sending offer`,
  `received answer` and `buffered early transport message`. The last one means packets
  from the device reach the relay, but the path has not been negotiated yet.
- If `netbird status -d` shows the device as `Connecting` with a `Last connection update`
  but no handshake, signal messages do not arrive. Typical causes: sending on
  `ConnectStream` instead of `Send`, the wrong key, or an empty relay address in the answer.
- **First sync after a reboot ends immediately with a clean close.** When a peer restarts
  while the server still holds its old sync session, the server's `PeersUpdateManager`
  closes the peer's update channel twice (once for the new channel, once for the dead old
  connection) and can close the new sync stream right after the first network map, with
  gRPC status OK. The client reconnects two seconds later and stays up. The official Go
  client shows the same behaviour.

## Open items

1. More testing on real hardware: ESP32-S3, long-term runs, power saving, roaming.
2. Remote peers on a different relay server (needs a second relay connection).
3. Port-range rules (need a reported version >= 0.48.0, which also turns on lazy
   connections on remote peers; see the gate table).
4. Many remote peers: a dynamic peer table, WireGuard peers activated only on demand.
5. Optional: outbound filtering, IPv6 overlay, resolving NetBird DNS names.
