// SPDX-License-Identifier: Apache-2.0
// Decoding of a decrypted management SyncResponse into what netbird-lite uses: signal and relay
// configuration, our address, the remote peers and the inbound firewall rules. Pure C on top of
// nanopb, so it is unit-tested and fuzzed on the host (tests/host/test_rules.c, fuzz_wire.c).
//
// Robustness: every string, byte string and repeated field the server controls is read through a
// callback. A value that is longer than expected only affects its own entry and never makes nanopb
// reject the whole network map.
//
// Firewall rules fail closed: a rule that cannot be converted exactly (unknown protocol, port or
// source that does not parse or is out of range) is skipped and never widened to "any". Skipping
// an ACCEPT rule only removes access. A DROP rule cannot be skipped that way, so if one is
// unreadable or does not fit, no ACCEPT rule is kept at all (nothing passes inbound).
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nbl_acl.h"
#include "pb_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Bounded string for a nanopb FT_CALLBACK string field (pb_callback_t.arg). */
typedef struct {
    char *buf;
    size_t cap;
    bool seen; /* the field was present */
    bool bad;  /* longer than cap - 1 characters or containing a NUL: buf is "" */
} nbl_pb_str_t;

/** nanopb decode callback for nbl_pb_str_t: copies a string that fits, skips any other. Fails
 *  only on a broken stream, never because of the content. */
bool nbl_pb_decode_str(pb_istream_t *s, const pb_field_t *f, void **arg);

#define NBL_NM_URI_CAP 128           /* signal URI, including the NUL */
#define NBL_NM_RELAY_URL_CAP 160     /* relay URL, as nbl_relay stores it */
#define NBL_NM_TOKEN_PAYLOAD_CAP 32  /* relay token payload (a Unix timestamp) */
#define NBL_NM_TOKEN_SIG_CAP 96      /* relay token signature (base64 HMAC-SHA256: 44) */
#define NBL_NM_KEY_CAP 45            /* base64 WireGuard key (44) */
#define NBL_NM_ADDR_CAP 20           /* "a.b.c.d/nn" */
#define NBL_NM_MAX_SOURCES 4         /* IPv4 source prefixes per firewall rule (the server sends 1) */

typedef struct {
    char key[NBL_NM_KEY_CAP];
    uint32_t ip4; /* overlay address (network byte order): the first IPv4 /32 in allowedIps */
} nbl_nm_peer_t;

typedef struct {
    /* Set by the caller, kept by nbl_netmap_decode(): */
    nbl_nm_peer_t *peers;   /* room for max_peers entries */
    int max_peers;
    nbl_acl_rule_t *rules;  /* room for max_rules entries */
    int max_rules;
    const char *own_key;    /* our public key (base64): skipped in the peer list. May be NULL. */

    /* Results. NetbirdConfig: */
    bool has_signal;        /* signal_uri is set */
    char signal_uri[NBL_NM_URI_CAP];
    int32_t signal_protocol; /* HostConfig.Protocol: 0 UDP (unset), 1 TCP, 2 HTTP, 3 HTTPS, 4 DTLS */
    bool has_relay;         /* relay_url and the token are set */
    char relay_url[NBL_NM_RELAY_URL_CAP]; /* the first rels:// URL, otherwise the first URL */
    char relay_payload[NBL_NM_TOKEN_PAYLOAD_CAP];
    char relay_sig[NBL_NM_TOKEN_SIG_CAP];
    int relay_urls;         /* relay URLs in the message */
    int relay_urls_too_long;
    bool config_too_long;   /* the signal URI or a relay token part did not fit and was ignored */

    /* NetworkMap: */
    bool has_map;
    uint64_t serial;
    bool has_peer_config;
    char address[NBL_NM_ADDR_CAP]; /* "" if absent or too long */
    int32_t mtu;
    int n_peers;            /* entries in peers[] */
    int peers_total;        /* remote peers in the map, without our own key */
    int peers_unusable;     /* of those: unreadable, or without a 44-character key or IPv4 /32 */
    int n_rules;            /* entries in rules[] */
    int fw_total;           /* firewall rules in the map */
    int fw_skipped;         /* not applicable: outbound, or IPv6 sources only */
    int fw_malformed;       /* could not be converted exactly: skipped */
    int fw_truncated;       /* entries that did not fit into rules[] */
    bool deny_lost;         /* a DROP rule was unreadable or did not fit: n_rules is 0 */

    const char *error;      /* nanopb error message if nbl_netmap_decode() failed */
} nbl_netmap_t;

/** Decodes a SyncResponse. Set peers/max_peers, rules/max_rules and own_key first; all other
 *  fields are reset. Returns 0, or -1 if the message is not valid protobuf (then nothing of it
 *  may be used). */
int nbl_netmap_decode(const uint8_t *buf, size_t len, nbl_netmap_t *nm);

/** Strict IPv4 parser for "a.b.c.d" and "a.b.c.d/n": decimal octets 0..255 without leading
 *  zeros, n = 0..32, nothing else. *ip in network byte order; *prefix = -1 without "/n". */
bool nbl_nm_parse_ip4(const char *s, uint32_t *ip, int *prefix);

/** Netmask for a prefix length of 0..32, network byte order. */
uint32_t nbl_nm_mask4(unsigned prefix);

#ifdef __cplusplus
}
#endif
