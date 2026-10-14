// SPDX-License-Identifier: Apache-2.0
// netbird-lite: lightweight NetBird client for ESP32 (ESP-IDF >= 5.4)
//
//   Management (gRPC/HTTP2, NaCl box) -> login/sync -> peers, relay token, firewall rules
//   Signal     (gRPC/HTTP2, NaCl box) -> offer/answer with remote peers
//   Relay      (WebSocket over TLS)   -> WireGuard packets, no direct UDP path needed
//   WireGuard  (wireguard-lwip)       -> lwIP netif with the NetBird address
//
// Not included: ICE/STUN/TURN (all traffic goes through the relay), SSH, DNS, routes, Rosenpass,
// lazy connections, IPv6, SSO login (setup keys only).
//
// Relay: one relay connection, to the first rels:// URL that management announces. Remote peers
// must be connected to the same relay instance; there is no second relay connection.
//
// Version: the device reports NetBird version 0.44.0 with the netbird-lite release as build
// metadata ("0.44.0+netbird-lite.0.3.0"). Official peers therefore keep a permanent connection
// (no lazy connections, which need >= 0.45.0), and the management server sends firewall rules
// without port ranges (>= 0.48.0): a policy port range other than a single port does not reach
// the device, and its traffic stays blocked. See NBL_VERSION in src/nbl_ctrl.c.
//
// Inbound firewall: inbound ACCEPT and DROP rules are enforced; a rule that cannot be converted
// exactly is skipped, never widened. If a DROP rule cannot be applied, no inbound traffic is
// accepted until the next network map. Replies to connections the device opened always pass.
#pragma once

/** Version of this component (also sent as user agent and in the reported NetBird version). */
#define NETBIRD_LITE_VERSION "0.3.0"

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /** Required, e.g. "https://connect.example.com" or "https://host:33073". */
    const char *management_url;
    /** Setup key for the registration. It is only sent until the management server has accepted
     *  the device key once (flag in NVS), and again if the server reports the peer as not
     *  registered. NULL is allowed for a device that is already registered: the login then uses
     *  the stored key alone and fails (NBL_FATAL) only if the server rejects it. */
    const char *setup_key;
    /** Peer name shown in the dashboard. NULL or "" = "esp32-xxxxxx" (last 3 bytes of the MAC). */
    const char *hostname;
} nbl_config_t;

typedef enum {
    NBL_IDLE = 0,     /* not started, or stopped */
    NBL_WAIT_TIME,    /* waiting for a valid system time (needed by TLS and WireGuard) */
    NBL_CONNECTING,   /* TLS connection to the management server */
    NBL_LOGIN,        /* GetServerKey / Login */
    NBL_SYNCED,       /* sync stream open, network map received */
    NBL_RETRY_WAIT,   /* connection lost or temporary error: retry after 1..45 s (backoff, jitter) */
    NBL_FATAL,        /* see last_error. Login rejected (setup key invalid, expired, revoked or used
                         up; peer not registered and no setup key): retried every 5 minutes, in case
                         the administrator fixes it. Or nbl_start() failed because the stored device
                         key could not be read: no retry, the key is never replaced silently. */
} nbl_state_t;

typedef struct {
    nbl_state_t state;
    char pubkey[48];       /* WireGuard public key (base64), as shown in the dashboard */
    char ip[20];           /* NetBird address "a.b.c.d/p", empty until the first sync */
    char last_error[96];
    bool signal_up, relay_up;
    int peers;             /* remote peers in the network map (at most CONFIG_NBL_MAX_PEERS) */
    int peers_up;          /* of those, peers with a valid WireGuard keypair */
    int acl_rules;         /* inbound firewall entries in effect */
    uint32_t relay_rx, relay_tx, relay_dropped, relay_reconnects; /* relay packet/connection counters */
    uint32_t acl_pass, acl_drop; /* inbound packets passed/dropped by the firewall */
} nbl_status_t;

/** Starts the client tasks and returns immediately. Requires nvs_flash_init() and esp_netif with a
 *  network connection. Can be called once: later calls, also after nbl_stop(), return
 *  ESP_ERR_INVALID_STATE (a restart needs a reboot). Errors: ESP_ERR_INVALID_ARG (URL missing,
 *  malformed or longer than 127 characters, setup key longer than 63), an NVS error if the stored
 *  device key cannot be read (state NBL_FATAL), ESP_ERR_NO_MEM. */
esp_err_t nbl_start(const nbl_config_t *cfg);
/** Signals the tasks to stop and returns without waiting. Partial implementation: the WireGuard netif
 *  stays in place, and nbl_start() cannot be called again before a reboot. */
void nbl_stop(void);
/** Thread-safe: copies a consistent snapshot (all zero before nbl_start()). */
void nbl_get_status(nbl_status_t *out);

/** Erases the stored key and registration flag (new identity on the next start, which then needs a
 *  setup key). Call it before nbl_start(): a running client keeps its key until the next reboot. */
void nbl_forget(void);

#ifdef __cplusplus
}
#endif
