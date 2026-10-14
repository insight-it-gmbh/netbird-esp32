// libFuzzer target for the stateful inbound filter (nbl_acl.c): a rule set from the input, then a
// sequence of packets in both directions through nbl_acl_track()/nbl_acl_check() with a moving
// clock. Besides the sanitizers two invariants are checked: no packet for another address ever
// passes, and the reply to a packet that was just tracked always passes, even without rules.
//
// Input: [n][n x 8 bytes rule][4 bytes start clock] then records [ctl][...] until the end.
//   ctl bit 0: 0 = outbound (track), 1 = inbound (check); bits 1-3: clock step; bit 4: raw packet
//   ([len][len bytes]) instead of a structured one ([6 bytes], see build()); ctl 0xff: re-init.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nbl_acl.h"

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t x[4] = {a, b, c, d};
    uint32_t v;
    memcpy(&v, x, 4);
    return v;
}

static uint32_t addr(unsigned i)
{
    static const uint8_t t[8][4] = {
        {100, 64, 0, 10}, {100, 64, 0, 20}, {100, 64, 0, 21}, {100, 64, 1, 1},
        {10, 0, 0, 1},    {0, 0, 0, 0},     {255, 255, 255, 255}, {100, 64, 0, 11},
    };
    return ip4(t[i & 7][0], t[i & 7][1], t[i & 7][2], t[i & 7][3]);
}

#define LOCAL addr(0)

static uint16_t port(uint8_t s)
{
    static const uint16_t small[7] = {53, 80, 443, 0, 65535, 5000, 40000};
    return (s & 0x80) ? (uint16_t)(s * 257u) : small[s % 7];
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Structured packet from 6 input bytes:
 *   a: bits 0-2 remote address, bit 3 local address replaced by another one, bits 4-5 protocol
 *      (ICMP, TCP, UDP, GRE), bits 6-7 option words
 *   b, c: remote / local port selector; ICMP: type selector / identifier
 *   d: TCP flags
 *   e: bits 0-1 fragment (none, first with MF, trailing with MF, last), bits 2-7 identification
 *   f: bit 7 set -> truncate to f & 0x7f bytes
 * The packet goes local -> remote when out, else remote -> local. Returns its length; *trackable
 * tells whether nbl_acl_track() must create an entry for it. */
static size_t build(uint8_t *b, const uint8_t *in, bool out, bool *trackable)
{
    static const uint8_t protos[4] = {1, 6, 17, 47};
    uint8_t proto = protos[(in[0] >> 4) & 3];
    size_t hl = 20 + 4u * (in[0] >> 6);
    uint32_t remote = addr(in[0]), local = (in[0] & 8) ? addr(in[0] + 1u) : LOCAL;
    uint16_t rport = port(in[1]), lport = port(in[2]);
    unsigned fr = in[4] & 3;
    memset(b, 0, NBL_ACL_HDR_MAX);
    b[0] = (uint8_t)(0x40 | (hl / 4));
    put16(b + 4, (uint16_t)(in[4] >> 2));
    b[6] = (uint8_t)((fr == 1 || fr == 2) ? 0x20 : 0);
    b[7] = (uint8_t)(fr >= 2 ? 185 : 0);
    b[8] = 64;
    b[9] = proto;
    memcpy(b + 12, out ? &local : &remote, 4);
    memcpy(b + 16, out ? &remote : &local, 4);
    memset(b + 20, 1, hl - 20); /* NOP options */
    uint8_t *t = b + hl;
    size_t tl = 8;
    if (proto == 1) {
        static const uint8_t types[4] = {8, 0, 3, 11};
        t[0] = (in[1] & 0x80) ? in[1] : types[in[1] & 3];
        put16(t + 4, in[2]);
    } else {
        put16(t, out ? lport : rport);
        put16(t + 2, out ? rport : lport);
        if (proto == 6) {
            t[12] = 0x50;
            t[13] = in[3];
            tl = 20;
        }
    }
    size_t len = hl + tl;
    if (in[5] & 0x80 && (size_t)(in[5] & 0x7f) < len) {
        len = in[5] & 0x7f;
    }
    *trackable = out && local == LOCAL && fr <= 1 && len == hl + tl && proto != 47 &&
                 (proto != 1 || t[0] == 8);
    return len;
}

/* the reply to an outbound packet built by build(): addresses and ports swapped, echo reply */
static size_t mirror(uint8_t *r, const uint8_t *b, size_t len)
{
    memcpy(r, b, len);
    memcpy(r + 12, b + 16, 4);
    memcpy(r + 16, b + 12, 4);
    r[6] = r[7] = 0;
    size_t hl = (size_t)(b[0] & 15) * 4;
    if (b[9] == 1) {
        r[hl] = 0;
    } else {
        memcpy(r + hl, b + hl + 2, 2);
        memcpy(r + hl + 2, b + hl, 2);
    }
    return len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nbl_acl_state_t st;
    nbl_acl_rule_t rules[15];
    if (size < 5) {
        return 0;
    }
    size_t n = data[0] & 15, pos = 1;
    if (size < pos + n * 8 + 4) {
        return 0;
    }
    for (size_t i = 0; i < n; i++, pos += 8) {
        const uint8_t *r = data + pos;
        static const uint8_t protos[8] = {0, 0, 1, 6, 17, 6, 17, 47};
        uint32_t m = (r[1] % 33) ? ~0u << (32 - r[1] % 33) : 0; /* prefix length 0..32 */
        rules[i] = (nbl_acl_rule_t){
            .src = addr(r[0]),
            .mask = ip4((uint8_t)(m >> 24), (uint8_t)(m >> 16), (uint8_t)(m >> 8), (uint8_t)m),
            .proto = (r[2] & 0x80) ? r[2] : protos[r[2] & 7],
            .action = (r[3] & 0x80) ? r[3] : (r[3] & 1),
            .p0 = (uint16_t)(r[4] << 8 | r[5]),
            .p1 = (uint16_t)(r[6] << 8 | r[7]),
        };
        if ((r[3] & 0x40) && rules[i].p0 > rules[i].p1) { /* mostly sane ranges, some empty */
            uint16_t x = rules[i].p0;
            rules[i].p0 = rules[i].p1;
            rules[i].p1 = x;
        }
    }
    uint32_t now = (uint32_t)data[pos] << 24 | (uint32_t)data[pos + 1] << 16 |
                   (uint32_t)data[pos + 2] << 8 | data[pos + 3];
    pos += 4;
    nbl_acl_init(&st, LOCAL);

    static const uint32_t steps[8] = {0, 1, 9, 10, 30, 120, 7200, 65536};
    uint8_t b[NBL_ACL_HDR_MAX], r[NBL_ACL_HDR_MAX];
    while (pos < size) {
        uint8_t c = data[pos++];
        if (c == 0xff) {
            nbl_acl_init(&st, LOCAL);
            continue;
        }
        bool out = !(c & 1);
        now += steps[(c >> 1) & 7];
        size_t len;
        bool trackable = false;
        if (c & 0x10) {
            if (pos >= size) {
                break;
            }
            len = data[pos++] % (NBL_ACL_HDR_MAX + 1);
            if (len > size - pos) {
                len = size - pos;
            }
            memcpy(b, data + pos, len);
            pos += len;
        } else {
            if (size - pos < 6) {
                break;
            }
            len = build(b, data + pos, out, &trackable);
            pos += 6;
        }
        if (out) {
            nbl_acl_track(&st, b, len, now);
            if (trackable && !nbl_acl_check(&st, NULL, 0, r, mirror(r, b, len), now)) {
                abort(); /* the reply to a just tracked packet must pass */
            }
        } else if (nbl_acl_check(&st, rules, n, b, len, now)) {
            uint32_t dst = 0;
            if (len < 20 || (memcpy(&dst, b + 16, 4), dst != LOCAL)) {
                abort(); /* passed although not addressed to us */
            }
        }
    }
    return 0;
}
