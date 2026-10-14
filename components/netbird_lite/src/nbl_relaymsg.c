// SPDX-License-Identifier: MIT
#include "nbl_relaymsg.h"

#include <string.h>

int nbl_relay_parse(const uint8_t *msg, size_t len, nbl_relay_msg_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!msg || len < 2 || msg[0] != NBL_R_PROTO) {
        return -1;
    }
    out->type = msg[1];
    switch (out->type) {
    case NBL_R_TRANSPORT:
        if (len < 2 + NBL_RELAY_ID_LEN || len - 2 - NBL_RELAY_ID_LEN > NBL_R_MAX_TRANSPORT_PAYLOAD) {
            return -1;
        }
        out->id = msg + 2;
        out->payload = msg + 2 + NBL_RELAY_ID_LEN;
        out->payload_len = len - 2 - NBL_RELAY_ID_LEN;
        return 0;
    case NBL_R_AUTH_RESP:
        if (len < 3) {
            return -1; /* no instance URL (upstream UnmarshalAuthResponse) */
        }
        out->payload = msg + 2;
        out->payload_len = len - 2;
        return 0;
    case NBL_R_CLOSE:
    case NBL_R_HEALTH:
        return 0;
    default:
        return -1;
    }
}

int nbl_relay_build_auth(uint8_t *out, size_t cap, const uint8_t peer_id[NBL_RELAY_ID_LEN],
                         const uint8_t sig[32], const char *payload)
{
    size_t pl = strlen(payload);
    size_t need = 2 + 4 + NBL_RELAY_ID_LEN + 1 + 32 + pl;
    if (need > cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = NBL_R_PROTO;
    out[o++] = NBL_R_AUTH;
    static const uint8_t magic[4] = {0x21, 0x12, 0xA4, 0x42};
    memcpy(out + o, magic, 4);
    o += 4;
    memcpy(out + o, peer_id, NBL_RELAY_ID_LEN);
    o += NBL_RELAY_ID_LEN;
    out[o++] = 1; /* HMAC-SHA256 */
    memcpy(out + o, sig, 32);
    o += 32;
    memcpy(out + o, payload, pl);
    return (int)(o + pl);
}

int nbl_relay_build_transport(uint8_t *out, size_t cap, const uint8_t dst_id[NBL_RELAY_ID_LEN],
                              const uint8_t *wg, size_t wg_len)
{
    size_t need = 2 + NBL_RELAY_ID_LEN + wg_len;
    if (need > cap || need > NBL_R_MAX_MSG) {
        return -1;
    }
    out[0] = NBL_R_PROTO;
    out[1] = NBL_R_TRANSPORT;
    memcpy(out + 2, dst_id, NBL_RELAY_ID_LEN);
    memcpy(out + 2 + NBL_RELAY_ID_LEN, wg, wg_len);
    return (int)need;
}

static int is_host_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '.' || c == '_';
}

int nbl_relay_parse_url(const char *url, char *host, size_t host_cap, uint16_t *port)
{
    if (strncmp(url, "rels://", 7) != 0) {
        return -1;
    }
    const char *h = url + 7;
    size_t hl = 0;
    while (is_host_char(h[hl])) {
        hl++;
    }
    if (hl == 0 || hl >= host_cap) {
        return -1;
    }
    const char *p = h + hl;
    unsigned long pt = 443;
    if (*p == ':') {
        size_t nd = 0;
        pt = 0;
        for (p++; *p >= '0' && *p <= '9' && nd < 5; p++, nd++) {
            pt = pt * 10 + (unsigned long)(*p - '0');
        }
        if (nd == 0 || pt == 0 || pt > 65535) {
            return -1;
        }
    }
    if (*p != '\0' && *p != '/') {
        return -1; /* '[' (IPv6 literal), '@' (user info), a sixth port digit, ... */
    }
    memcpy(host, h, hl);
    host[hl] = 0;
    *port = (uint16_t)pt;
    return 0;
}
