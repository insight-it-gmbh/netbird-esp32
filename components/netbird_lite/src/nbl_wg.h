// SPDX-License-Identifier: Apache-2.0
// WireGuard as an lwIP network interface (wireguard-lwip), using the NetBird relay instead of UDP
// as transport.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Called from lwIP context with the peer tag (table index + 1) whenever WireGuard sends a packet.
 *  Must not block. */
typedef int (*nbl_wg_tx_fn)(int tag, const uint8_t *pkt, size_t len);

esp_err_t nbl_wg_init(const uint8_t priv[32], nbl_wg_tx_fn tx);
/** ip4 in network byte order, prefix 1..32, mtu 576..1420. May be called again when the address
 *  changes. ESP_OK only once the interface is fully configured (added, up, link up, address, MTU);
 *  otherwise nothing routes through it yet and the caller should retry. */
esp_err_t nbl_wg_set_ip(uint32_t ip4, uint8_t prefix, int mtu);
/** Returns the WireGuard slot or -1. tag = table index + 1 of the peer (1..65535). A key that is
 *  still registered is replaced (new session), so remove + add with a new address also works if
 *  the removal failed. */
int nbl_wg_add_peer(const char *pub_b64, uint32_t allowed_ip4, uint8_t prefix, int tag);
/** ESP_OK = the slot is free now. */
esp_err_t nbl_wg_remove_peer(int slot);
/** Starts handshakes with the peer. ESP_OK = requested; otherwise retry later. */
esp_err_t nbl_wg_connect(int slot);
bool nbl_wg_peer_up(int slot);
/** Thread-safe and non-blocking: copies the packet and queues it for the TCP/IP thread. Packets
 *  longer than MTU + 48 bytes, or beyond 16 KB queued, are dropped and counted as rx_bad. */
void nbl_wg_rx(int tag, const uint8_t *pkt, size_t len);

#include "nbl_acl.h"

/** Replaces the rule set atomically (the rules are copied). Replies to connections opened by this
 *  device always pass; n == 0 -> nothing else passes. On error the previous rules stay in force
 *  and the caller should retry. */
esp_err_t nbl_acl_set(const nbl_acl_rule_t *rules, size_t n);
/** Turns filtering on or off (off = allow everything). Thread-safe. */
void nbl_acl_enforce(bool on);

typedef struct {
    uint32_t acl_drop, acl_pass; /* inbound packets dropped/passed by the firewall */
    uint32_t rx_bad;             /* relay packets dropped before WireGuard (size, queue, memory) */
} nbl_wg_stats_t;
/** Thread-safe. */
void nbl_wg_stats(nbl_wg_stats_t *s);

#ifdef __cplusplus
}
#endif
