// SPDX-License-Identifier: MIT
// Pure relay protocol functions (NetBird relay protocol v1): messages and the server URL.
// No dependencies.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "nbl_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wire values as in upstream shared/relay/messages. Types 1/2 (removed legacy hello) and
 * 8-11 (peer state subscription) are not used. */
#define NBL_R_PROTO 1
#define NBL_R_TRANSPORT 3
#define NBL_R_CLOSE 4
#define NBL_R_HEALTH 5
#define NBL_R_AUTH 6
#define NBL_R_AUTH_RESP 7
#define NBL_R_MAX_MSG 8820 /* upstream messages.MaxMessageSize */
/* Largest transport payload (one WireGuard packet) accepted from the relay: tunnel MTU
 * (at most 1420, CONFIG_NBL_MTU) padded to 16 bytes, plus 32 bytes WireGuard data overhead
 * (16-byte header, 16-byte tag), plus margin. Larger ones are dropped. */
#define NBL_R_MAX_TRANSPORT_PAYLOAD 1500

typedef struct {
    uint8_t type;                        /* NBL_R_* or 0 = invalid */
    const uint8_t *id;                   /* NBL_RELAY_ID_LEN bytes, TRANSPORT only */
    const uint8_t *payload;              /* TRANSPORT/AUTH_RESP only */
    size_t payload_len;
} nbl_relay_msg_t;

/* Parses a message from the server. Returns 0 on success, -1 for unknown types (including
 * client-only types such as AUTH), truncated messages, an AUTH_RESP without an instance URL
 * and transport payloads above NBL_R_MAX_TRANSPORT_PAYLOAD. */
int nbl_relay_parse(const uint8_t *msg, size_t len, nbl_relay_msg_t *out);

/* Builds an auth message: version, type, magic, peer ID, token (algorithm byte, HMAC-SHA256
 * signature, payload). Returns its length or -1. */
int nbl_relay_build_auth(uint8_t *out, size_t cap, const uint8_t peer_id[NBL_RELAY_ID_LEN],
                         const uint8_t sig[32], const char *payload);

/* Builds a transport message. Returns its length or -1. */
int nbl_relay_build_transport(uint8_t *out, size_t cap, const uint8_t dst_id[NBL_RELAY_ID_LEN],
                              const uint8_t *wg, size_t wg_len);

/* Parses a relay server URL "rels://host[:port][/path]" (the path is ignored: the WebSocket
 * path is always /relay). The port defaults to 443 and must be 1..65535; the host may only
 * contain letters, digits, '-', '.' and '_'. Returns 0, or -1 for other schemes (rel://, plain
 * WebSocket, is not implemented), IPv6 literals ("[...]", not supported), user info, a host
 * that does not fit host_cap and any other malformed input. */
int nbl_relay_parse_url(const char *url, char *host, size_t host_cap, uint16_t *port);

#ifdef __cplusplus
}
#endif
