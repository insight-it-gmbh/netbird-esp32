// SPDX-License-Identifier: MIT
#include "nbl_acl.h"

#include <string.h>

#define P_ICMP 1
#define P_TCP 6
#define P_UDP 17

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO 8

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/* nbl_ct_entry_t.flags */
#define CT_FIN_OUT 0x01
#define CT_FIN_IN 0x02
#define CT_RST 0x04

/* idle timeouts in seconds */
#define TO_TCP 7200
#define TO_TCP_CLOSED 10 /* RST or FIN in both directions: room for the last ACK/retransmits */
#define TO_UDP 120
#define TO_ICMP 30
#define TO_FRAG 30 /* counted from the first fragment, like the official client */

typedef struct {
    uint32_t src, dst;     /* network byte order */
    uint16_t id;           /* IPv4 identification */
    uint16_t sport, dport; /* TCP/UDP ports; ICMP echo: both are the identifier */
    uint8_t proto;
    uint8_t tcp_flags;
    uint8_t icmp_type;
    bool first; /* fragment offset 0 (also every unfragmented packet) */
    bool more;  /* more fragments follow */
    bool l4;    /* first fragment carrying the complete transport header */
} pkt_t;

static bool parse(const uint8_t *b, size_t len, pkt_t *p)
{
    if (!b || len < 20 || (b[0] >> 4) != 4) {
        return false;
    }
    size_t hl = (size_t)(b[0] & 0x0f) * 4;
    if (hl < 20 || hl > len) {
        return false;
    }
    memset(p, 0, sizeof(*p));
    p->proto = b[9];
    memcpy(&p->src, b + 12, 4);
    memcpy(&p->dst, b + 16, 4);
    p->id = (uint16_t)(b[4] << 8 | b[5]);
    p->first = (b[6] & 0x1f) == 0 && b[7] == 0;
    p->more = (b[6] & 0x20) != 0;
    if (!p->first) {
        return true;
    }
    const uint8_t *t = b + hl;
    size_t tl = len - hl;
    if ((p->proto == P_TCP && tl >= 20) || (p->proto == P_UDP && tl >= 8)) {
        p->sport = (uint16_t)(t[0] << 8 | t[1]);
        p->dport = (uint16_t)(t[2] << 8 | t[3]);
        p->tcp_flags = p->proto == P_TCP ? t[13] : 0;
        p->l4 = true;
    } else if (p->proto == P_ICMP && tl >= 8) {
        p->icmp_type = t[0];
        p->sport = p->dport = (uint16_t)(t[4] << 8 | t[5]);
        p->l4 = true;
    }
    return true;
}

static bool rule_hit(const nbl_acl_rule_t *r, uint32_t src, uint8_t proto, bool has_port,
                     uint16_t dport)
{
    if ((src & r->mask) != (r->src & r->mask)) {
        return false;
    }
    if (r->proto && r->proto != proto) {
        return false;
    }
    if (r->p0 || r->p1) {
        if (!has_port || dport < r->p0 || dport > r->p1) {
            return false;
        }
    }
    return true;
}

bool nbl_acl_match(const nbl_acl_rule_t *rules, size_t n, uint32_t src, uint8_t proto,
                   bool has_port, uint16_t dport)
{
    if (!rules) {
        return false;
    }
    bool accept = false;
    for (size_t i = 0; i < n; i++) {
        if (rule_hit(&rules[i], src, proto, has_port, dport)) {
            if (rules[i].action != NBL_ACL_ACCEPT) {
                return false; /* DROP wins regardless of rule order */
            }
            accept = true;
        }
    }
    return accept;
}

/* ---------------- Connection tracking ---------------- */

static uint32_t ct_timeout(const nbl_ct_entry_t *e)
{
    if (e->proto == P_TCP) {
        bool fins = (e->flags & (CT_FIN_OUT | CT_FIN_IN)) == (CT_FIN_OUT | CT_FIN_IN);
        return (e->flags & CT_RST) || fins ? TO_TCP_CLOSED : TO_TCP;
    }
    return e->proto == P_UDP ? TO_UDP : TO_ICMP;
}

static bool ct_live(const nbl_ct_entry_t *e, uint32_t now)
{
    return e->proto && now - e->seen < ct_timeout(e);
}

static nbl_ct_entry_t *ct_find(nbl_acl_state_t *st, uint8_t proto, uint32_t ip, uint16_t rport,
                               uint16_t lport, uint32_t now)
{
    for (size_t i = 0; i < CONFIG_NBL_CT_ENTRIES; i++) {
        nbl_ct_entry_t *e = &st->ct[i];
        if (e->proto == proto && e->ip == ip && e->rport == rport && e->lport == lport &&
            ct_live(e, now)) {
            return e;
        }
    }
    return NULL;
}

/* a free or expired entry, otherwise the least recently used one */
static nbl_ct_entry_t *ct_victim(nbl_acl_state_t *st, uint32_t now)
{
    nbl_ct_entry_t *v = &st->ct[0];
    for (size_t i = 0; i < CONFIG_NBL_CT_ENTRIES; i++) {
        nbl_ct_entry_t *e = &st->ct[i];
        if (!ct_live(e, now)) {
            return e;
        }
        if (now - e->seen > now - v->seen) {
            v = e;
        }
    }
    return v;
}

static uint8_t ct_bits(uint8_t tcp_flags, uint8_t fin)
{
    return (uint8_t)(((tcp_flags & TCP_RST) ? CT_RST : 0) | ((tcp_flags & TCP_FIN) ? fin : 0));
}

void nbl_acl_init(nbl_acl_state_t *st, uint32_t local_ip)
{
    memset(st, 0, sizeof(*st));
    st->local_ip = local_ip;
}

void nbl_acl_track(nbl_acl_state_t *st, const uint8_t *pkt, size_t len, uint32_t now)
{
    pkt_t p;
    if (!parse(pkt, len, &p) || !p.l4 || !st->local_ip || p.src != st->local_ip) {
        return;
    }
    if (p.proto == P_ICMP && p.icmp_type != ICMP_ECHO) {
        return;
    }
    /* Every outbound TCP packet creates or refreshes its entry, not only SYN: an evicted entry of
     * an established connection comes back with the next ACK. Outbound packets only exist for
     * connections the stack opened or for inbound packets that already passed the filter. */
    nbl_ct_entry_t *e = ct_find(st, p.proto, p.dst, p.dport, p.sport, now);
    if (!e) {
        e = ct_victim(st, now);
        *e = (nbl_ct_entry_t){.ip = p.dst, .rport = p.dport, .lport = p.sport, .proto = p.proto};
    } else if ((p.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        e->flags = 0; /* new connection on a port pair that just closed */
    }
    e->seen = now;
    e->flags |= ct_bits(p.tcp_flags, CT_FIN_OUT);
}

static bool ct_reply(nbl_acl_state_t *st, const pkt_t *p, uint32_t now)
{
    if (!p->l4 || (p->proto == P_ICMP && p->icmp_type != ICMP_ECHO_REPLY)) {
        return false;
    }
    nbl_ct_entry_t *e = ct_find(st, p->proto, p->src, p->sport, p->dport, now);
    if (!e) {
        return false;
    }
    e->seen = now;
    e->flags |= ct_bits(p->tcp_flags, CT_FIN_IN);
    return true;
}

/* ---------------- Fragments ---------------- */

static nbl_frag_entry_t *frag_find(nbl_acl_state_t *st, const pkt_t *p)
{
    for (size_t i = 0; i < NBL_ACL_FRAG_ENTRIES; i++) {
        nbl_frag_entry_t *f = &st->frag[i];
        if (f->used && f->src == p->src && f->id == p->id && f->proto == p->proto) {
            return f;
        }
    }
    return NULL;
}

/* First fragment of a fragmented datagram: remember a pass for the trailing fragments, forget an
 * older verdict on a drop (a re-sent first fragment must not inherit it). */
static void frag_note(nbl_acl_state_t *st, const pkt_t *p, bool pass, uint32_t now)
{
    nbl_frag_entry_t *f = frag_find(st, p);
    if (!pass) {
        if (f) {
            f->used = 0;
        }
        return;
    }
    if (!f) {
        f = &st->frag[0]; /* a free entry, otherwise the oldest */
        for (size_t i = 1; i < NBL_ACL_FRAG_ENTRIES && f->used; i++) {
            nbl_frag_entry_t *g = &st->frag[i];
            if (!g->used || now - g->since > now - f->since) {
                f = g;
            }
        }
    }
    *f = (nbl_frag_entry_t){.src = p->src, .since = now, .id = p->id, .proto = p->proto, .used = 1};
}

bool nbl_acl_check(nbl_acl_state_t *st, const nbl_acl_rule_t *rules, size_t n,
                   const uint8_t *pkt, size_t len, uint32_t now)
{
    pkt_t p;
    /* only packets for our own address: never forward into other networks */
    if (!parse(pkt, len, &p) || !st->local_ip || p.dst != st->local_ip) {
        return false;
    }
    if (!p.first) {
        /* no transport header: inherit the verdict of the first fragment */
        nbl_frag_entry_t *f = frag_find(st, &p);
        return f && now - f->since < TO_FRAG;
    }
    bool tcpudp = p.proto == P_TCP || p.proto == P_UDP;
    bool pass;
    if (tcpudp && !p.l4) {
        pass = false; /* the ports cannot be checked (tiny first fragment, truncated packet) */
    } else {
        pass = ct_reply(st, &p, now) || nbl_acl_match(rules, n, p.src, p.proto, tcpudp, p.dport);
    }
    if (p.more) {
        frag_note(st, &p, pass, now);
    }
    return pass;
}
