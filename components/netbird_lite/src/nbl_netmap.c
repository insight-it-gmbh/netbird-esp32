// SPDX-License-Identifier: Apache-2.0
#include "nbl_netmap.h"

#include <string.h>

#include "nbl_mgmt.pb.h"
#include "pb_decode.h"

/* ============================== Strict parsers ============================== */

/* Decimal number of at most max_digits digits, no sign, no leading zero, value <= max. */
static bool parse_dec(const char **s, unsigned max_digits, uint32_t max, uint32_t *out)
{
    const char *p = *s;
    uint32_t v = 0;
    unsigned n = 0;
    while (*p >= '0' && *p <= '9') {
        if (++n > max_digits || (n == 2 && v == 0)) {
            return false;
        }
        v = v * 10 + (uint32_t)(*p++ - '0');
    }
    if (n == 0 || v > max) {
        return false;
    }
    *s = p;
    *out = v;
    return true;
}

bool nbl_nm_parse_ip4(const char *s, uint32_t *ip, int *prefix)
{
    uint8_t b[4];
    uint32_t v;
    for (int i = 0; i < 4; i++) {
        if (i > 0 && *s++ != '.') {
            return false;
        }
        if (!parse_dec(&s, 3, 255, &v)) {
            return false;
        }
        b[i] = (uint8_t)v;
    }
    int pfx = -1;
    if (*s == '/') {
        s++;
        if (!parse_dec(&s, 2, 32, &v)) {
            return false;
        }
        pfx = (int)v;
    }
    if (*s) {
        return false;
    }
    memcpy(ip, b, 4);
    *prefix = pfx;
    return true;
}

uint32_t nbl_nm_mask4(unsigned prefix)
{
    uint8_t m[4];
    for (unsigned i = 0; i < 4; i++) {
        unsigned bits = prefix > 8 * i ? prefix - 8 * i : 0;
        m[i] = bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits);
    }
    uint32_t r;
    memcpy(&r, m, 4);
    return r;
}

/* ============================== nanopb callbacks ============================== */

bool nbl_pb_decode_str(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    (void)f;
    nbl_pb_str_t *a = *arg;
    size_t n = s->bytes_left;
    a->seen = true;
    a->buf[0] = 0;
    if (n >= a->cap) {
        a->bad = true;
        return pb_read(s, NULL, n);
    }
    if (!pb_read(s, (pb_byte_t *)a->buf, n)) {
        return false;
    }
    a->buf[n] = 0;
    a->bad = strlen(a->buf) != n;
    if (a->bad) {
        a->buf[0] = 0;
    }
    return true;
}

/* RelayConfig.urls: keep the first rels:// URL (the only scheme nbl_relay implements), otherwise
 * the first URL. Only one relay connection exists: remote peers must use the same relay. */
static bool cb_relay_url(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    nbl_netmap_t *nm = *arg;
    char url[NBL_NM_RELAY_URL_CAP];
    nbl_pb_str_t a = {url, sizeof(url), false, false};
    void *pa = &a;
    if (!nbl_pb_decode_str(s, f, &pa)) {
        return false;
    }
    nm->relay_urls++;
    if (a.bad) {
        nm->relay_urls_too_long++;
        return true;
    }
    bool tls = !strncmp(url, "rels://", 7);
    if (!nm->relay_url[0] || (tls && strncmp(nm->relay_url, "rels://", 7) != 0)) {
        memcpy(nm->relay_url, url, sizeof(url));
    }
    return true;
}

typedef struct {
    char key[NBL_NM_KEY_CAP];
    nbl_pb_str_t key_arg;
    uint32_t ip4;
    bool have_ip;
} peer_ctx_t;

/* RemotePeerConfig.allowedIps: the peer's own address is the first IPv4 /32 (the server lists it
 * first, IPv6 follows); everything else is skipped. */
static bool cb_allowed_ip(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    peer_ctx_t *pc = *arg;
    char buf[48];
    nbl_pb_str_t a = {buf, sizeof(buf), false, false};
    void *pa = &a;
    if (!nbl_pb_decode_str(s, f, &pa)) {
        return false;
    }
    uint32_t ip;
    int pfx;
    if (!pc->have_ip && !a.bad && nbl_nm_parse_ip4(buf, &ip, &pfx) && pfx == 32) {
        pc->ip4 = ip;
        pc->have_ip = true;
    }
    return true;
}

/* Skips the rest of a list entry that failed to decode, so that the list can continue. */
static bool skip_rest(pb_istream_t *s)
{
    return pb_read(s, NULL, s->bytes_left);
}

static bool cb_remote_peer(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    (void)f;
    nbl_netmap_t *nm = *arg;
    peer_ctx_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.key_arg = (nbl_pb_str_t){pc.key, sizeof(pc.key), false, false};
    management_RemotePeerConfig rp = management_RemotePeerConfig_init_zero;
    rp.wgPubKey.funcs.decode = nbl_pb_decode_str;
    rp.wgPubKey.arg = &pc.key_arg;
    rp.allowedIps.funcs.decode = cb_allowed_ip;
    rp.allowedIps.arg = &pc;
    if (!pb_decode(s, management_RemotePeerConfig_fields, &rp)) {
        nm->peers_total++;
        nm->peers_unusable++;
        return skip_rest(s);
    }
    if (nm->own_key && !strcmp(pc.key, nm->own_key)) {
        return true; /* ourselves */
    }
    nm->peers_total++;
    if (strlen(pc.key) != NBL_NM_KEY_CAP - 1 || !pc.have_ip) {
        nm->peers_unusable++;
        return true;
    }
    for (int i = 0; i < nm->n_peers; i++) {
        if (!strcmp(nm->peers[i].key, pc.key)) {
            return true; /* listed twice */
        }
    }
    if (nm->n_peers < nm->max_peers) {
        nbl_nm_peer_t *p = &nm->peers[nm->n_peers++];
        memcpy(p->key, pc.key, sizeof(p->key));
        p->ip4 = pc.ip4;
    }
    return true;
}

typedef struct {
    char peer_ip[48];
    nbl_pb_str_t peer_ip_arg;
    char port[8];
    nbl_pb_str_t port_arg;
    uint8_t src[NBL_NM_MAX_SOURCES][5]; /* IPv4 address + prefix length */
    int n_src;                           /* IPv4 entries in src */
    int n_src_all;                       /* all sourcePrefixes entries */
    bool src_bad;                        /* invalid entry, or more IPv4 entries than fit */
} rule_ctx_t;

/* FirewallRule.sourcePrefixes: [IPv4 (4) | IPv6 (16)][prefix length] (shared/netiputil). */
static bool cb_src_prefix(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    (void)f;
    rule_ctx_t *rc = *arg;
    size_t n = s->bytes_left;
    uint8_t b[17];
    rc->n_src_all++;
    if (n != 5 && n != 17) {
        rc->src_bad = true;
        return pb_read(s, NULL, n);
    }
    if (!pb_read(s, b, n)) {
        return false;
    }
    if (n == 17) {
        static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (memcmp(b, v4mapped, 12) != 0) {
            if (b[16] > 128) {
                rc->src_bad = true;
            }
            return true; /* IPv6: never matches an IPv4 packet */
        }
        memmove(b, b + 12, 5); /* IPv4-mapped: as upstream DecodePrefix, an IPv4 prefix */
    }
    if (b[4] > 32 || rc->n_src == NBL_NM_MAX_SOURCES) {
        rc->src_bad = true;
        return true;
    }
    memcpy(rc->src[rc->n_src++], b, 5);
    return true;
}

/* ============================== Rule conversion ============================== */

static void add_rule(nbl_netmap_t *nm, const nbl_acl_rule_t *r)
{
    if (nm->n_rules < nm->max_rules) {
        nm->rules[nm->n_rules++] = *r;
        return;
    }
    nm->fw_truncated++;
    if (r->action == NBL_ACL_DROP) {
        /* a deny must not get lost to truncation: it takes the place of an ACCEPT entry */
        for (int i = nm->n_rules - 1; i >= 0; i--) {
            if (nm->rules[i].action != NBL_ACL_DROP) {
                nm->rules[i] = *r;
                return;
            }
        }
        nm->deny_lost = true;
    }
}

static void reject_rule(nbl_netmap_t *nm, bool drop)
{
    nm->fw_malformed++;
    if (drop) {
        nm->deny_lost = true;
    }
}

/* Port selection as the official client reads it (client/internal/acl/manager.go): PortInfo
 * unless it is empty (no selection, port 0 or the range 0-0, which the server sends for "all
 * ports"), then the legacy Port string ("" = any port). Ranges need a NetBird version >= 0.48.0,
 * so the server converts them for netbird-lite (single ports only, see NBL_VERSION). */
static bool rule_ports(const management_FirewallRule *fr, const rule_ctx_t *rc, uint16_t *p0, uint16_t *p1)
{
    if (fr->has_PortInfo) {
        const management_PortInfo *pi = &fr->PortInfo;
        if (pi->which_portSelection == management_PortInfo_port_tag && pi->portSelection.port != 0) {
            if (pi->portSelection.port > 65535) {
                return false;
            }
            *p0 = *p1 = (uint16_t)pi->portSelection.port;
            return true;
        }
        if (pi->which_portSelection == management_PortInfo_range_tag) {
            uint32_t a = pi->portSelection.range.start, b = pi->portSelection.range.end;
            if (a != 0 || b != 0) {
                if (a == 0 || a > b || b > 65535) {
                    return false;
                }
                *p0 = (uint16_t)a;
                *p1 = (uint16_t)b;
                return true;
            }
        }
    }
    if (rc->port_arg.bad) {
        return false;
    }
    if (!rc->port[0]) {
        *p0 = *p1 = 0;
        return true;
    }
    const char *p = rc->port;
    uint32_t v;
    if (!parse_dec(&p, 5, 65535, &v) || *p || v == 0) {
        return false;
    }
    *p0 = *p1 = (uint16_t)v;
    return true;
}

static void convert_rule(nbl_netmap_t *nm, const management_FirewallRule *fr, const rule_ctx_t *rc)
{
    bool drop;
    switch (fr->Action) {
    case management_RuleAction_RA_ACCEPT: drop = false; break;
    case management_RuleAction_RA_DROP: drop = true; break;
    default: reject_rule(nm, true); return; /* unknown action: may have been a deny */
    }
    /* Only inbound rules are enforced. Replies to connections the device opened pass the
     * connection tracking of nbl_acl, so outbound rules are not needed. */
    if (fr->Direction == management_RuleDirection_RD_OUT) {
        nm->fw_skipped++;
        return;
    }
    if (fr->Direction != management_RuleDirection_RD_IN) {
        reject_rule(nm, drop);
        return;
    }
    uint8_t proto;
    switch (fr->Protocol) {
    case management_RuleProtocol_RP_ALL: proto = 0; break;
    case management_RuleProtocol_RP_TCP: proto = 6; break;
    case management_RuleProtocol_RP_UDP: proto = 17; break;
    case management_RuleProtocol_RP_ICMP: proto = 1; break;
    case management_RuleProtocol_RP_CUSTOM:
        if (fr->customProtocol < 1 || fr->customProtocol > 255) {
            reject_rule(nm, drop); /* 0 would mean "any protocol" */
            return;
        }
        proto = (uint8_t)fr->customProtocol;
        break;
    default: reject_rule(nm, drop); return;
    }
    nbl_acl_rule_t r = {0};
    r.proto = proto;
    r.action = drop ? NBL_ACL_DROP : NBL_ACL_ACCEPT;
    if (!rule_ports(fr, rc, &r.p0, &r.p1) || ((r.p0 || r.p1) && proto != 0 && proto != 6 && proto != 17)) {
        reject_rule(nm, drop); /* unparsable, or ports for a protocol without ports */
        return;
    }
    if (rc->n_src_all > 0) { /* sourcePrefixes supersede PeerIP */
        if (rc->src_bad) {
            reject_rule(nm, drop);
            return;
        }
        if (rc->n_src == 0) {
            nm->fw_skipped++; /* IPv6 sources only */
            return;
        }
        for (int i = 0; i < rc->n_src; i++) {
            memcpy(&r.src, rc->src[i], 4);
            r.mask = nbl_nm_mask4(rc->src[i][4]);
            add_rule(nm, &r);
        }
        return;
    }
    if (rc->peer_ip_arg.bad) {
        reject_rule(nm, drop);
        return;
    }
    if (strchr(rc->peer_ip, ':')) {
        nm->fw_skipped++; /* IPv6 source */
        return;
    }
    uint32_t ip;
    int pfx;
    if (!nbl_nm_parse_ip4(rc->peer_ip, &ip, &pfx)) {
        reject_rule(nm, drop); /* also an empty PeerIP: no source is not "any source" */
        return;
    }
    if (pfx < 0) {
        pfx = ip == 0 ? 0 : 32; /* a bare address; 0.0.0.0 stands for every peer */
    }
    r.src = ip;
    r.mask = nbl_nm_mask4((unsigned)pfx);
    add_rule(nm, &r);
}

static bool cb_fw_rule(pb_istream_t *s, const pb_field_t *f, void **arg)
{
    (void)f;
    nbl_netmap_t *nm = *arg;
    rule_ctx_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.peer_ip_arg = (nbl_pb_str_t){rc.peer_ip, sizeof(rc.peer_ip), false, false};
    rc.port_arg = (nbl_pb_str_t){rc.port, sizeof(rc.port), false, false};
    management_FirewallRule fr = management_FirewallRule_init_zero;
    fr.PeerIP.funcs.decode = nbl_pb_decode_str;
    fr.PeerIP.arg = &rc.peer_ip_arg;
    fr.Port.funcs.decode = nbl_pb_decode_str;
    fr.Port.arg = &rc.port_arg;
    fr.sourcePrefixes.funcs.decode = cb_src_prefix;
    fr.sourcePrefixes.arg = &rc;
    nm->fw_total++;
    if (!pb_decode(s, management_FirewallRule_fields, &fr)) {
        reject_rule(nm, true); /* unreadable: it may have been a deny */
        return skip_rest(s);
    }
    convert_rule(nm, &fr, &rc);
    return true;
}

/* ============================== SyncResponse ============================== */

int nbl_netmap_decode(const uint8_t *buf, size_t len, nbl_netmap_t *nm)
{
    nbl_nm_peer_t *peers = nm->peers;
    int max_peers = peers ? nm->max_peers : 0;
    nbl_acl_rule_t *rules = nm->rules;
    int max_rules = rules ? nm->max_rules : 0;
    const char *own_key = nm->own_key;
    memset(nm, 0, sizeof(*nm));
    nm->peers = peers;
    nm->max_peers = max_peers;
    nm->rules = rules;
    nm->max_rules = max_rules;
    nm->own_key = own_key;

    nbl_pb_str_t uri = {nm->signal_uri, sizeof(nm->signal_uri), false, false};
    nbl_pb_str_t payload = {nm->relay_payload, sizeof(nm->relay_payload), false, false};
    nbl_pb_str_t sig = {nm->relay_sig, sizeof(nm->relay_sig), false, false};
    nbl_pb_str_t addr = {nm->address, sizeof(nm->address), false, false};
    management_SyncResponse r = management_SyncResponse_init_zero;
    r.netbirdConfig.signal.uri.funcs.decode = nbl_pb_decode_str;
    r.netbirdConfig.signal.uri.arg = &uri;
    r.netbirdConfig.relay.urls.funcs.decode = cb_relay_url;
    r.netbirdConfig.relay.urls.arg = nm;
    r.netbirdConfig.relay.tokenPayload.funcs.decode = nbl_pb_decode_str;
    r.netbirdConfig.relay.tokenPayload.arg = &payload;
    r.netbirdConfig.relay.tokenSignature.funcs.decode = nbl_pb_decode_str;
    r.netbirdConfig.relay.tokenSignature.arg = &sig;
    r.NetworkMap.peerConfig.address.funcs.decode = nbl_pb_decode_str;
    r.NetworkMap.peerConfig.address.arg = &addr;
    r.NetworkMap.remotePeers.funcs.decode = cb_remote_peer;
    r.NetworkMap.remotePeers.arg = nm;
    r.NetworkMap.FirewallRules.funcs.decode = cb_fw_rule;
    r.NetworkMap.FirewallRules.arg = nm;

    pb_istream_t is = pb_istream_from_buffer(buf, len);
    if (!pb_decode(&is, management_SyncResponse_fields, &r)) {
        nm->error = PB_GET_ERROR(&is);
        return -1;
    }
    if (r.has_netbirdConfig) {
        const management_NetbirdConfig *nc = &r.netbirdConfig;
        if (nc->has_signal && uri.seen) {
            nm->config_too_long |= uri.bad;
            nm->has_signal = nm->signal_uri[0] != 0;
            nm->signal_protocol = nc->signal.protocol;
        }
        if (nc->has_relay) {
            nm->config_too_long |= payload.bad || sig.bad;
            nm->has_relay = nm->relay_url[0] && nm->relay_sig[0] && !payload.bad && !sig.bad;
        }
    }
    if (r.has_NetworkMap) {
        nm->has_map = true;
        nm->serial = r.NetworkMap.Serial;
        nm->has_peer_config = r.NetworkMap.has_peerConfig;
        nm->mtu = r.NetworkMap.peerConfig.mtu;
    }
    if (nm->deny_lost) {
        nm->n_rules = 0;
    }
    return 0;
}
