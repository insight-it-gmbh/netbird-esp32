// Host unit tests for the pure modules: protobuf envelope helpers (nbl_wire.h), WebSocket
// framing, relay messages, gRPC framing and the inbound ACL. Plain C11, no ESP-IDF needed.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nbl_acl.h"
#include "nbl_grpc.h"
#include "nbl_relaymsg.h"
#include "nbl_ws.h"
#include <arpa/inet.h>
#include "nbl_wire.h"

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

struct col {
    uint8_t *d;
    size_t n;
    int c;
};

static void test_collect_msg(void *ctx, const uint8_t *m, size_t l)
{
    struct col *co = ctx;
    memcpy(co->d + co->n, m, l);
    co->n += l;
    co->c++;
}

static void test_wire(void)
{
    uint8_t b[64];
    /* varint boundaries */
    uint64_t vals[] = {0, 1, 127, 128, 300, 65535, 4294967295ULL, 0x7fffffffffffffffULL};
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        size_t n = nbl_put_varint(b, vals[i]);
        /* decode */
        uint64_t v = 0;
        int sh = 0;
        for (size_t j = 0; j < n; j++) {
            v |= (uint64_t)(b[j] & 0x7f) << sh;
            sh += 7;
        }
        CHECK(v == vals[i]);
        CHECK(n > 0 && n <= 10);
    }
    /* put/get bytes */
    size_t p = 0;
    p = nbl_put_bytes(b, p, 1, "hello", 5);
    p = nbl_put_bytes(b, p, 4, "\x01\x02", 2);
    p = nbl_put_int(b, p, 3, 42);
    const uint8_t *d;
    size_t dl;
    CHECK(nbl_get_bytes(b, p, 1, &d, &dl) == 0 && dl == 5 && memcmp(d, "hello", 5) == 0);
    CHECK(nbl_get_bytes(b, p, 4, &d, &dl) == 0 && dl == 2 && d[0] == 1);
    CHECK(nbl_get_bytes(b, p, 99, &d, &dl) != 0); /* field not present */
    /* truncated input */
    CHECK(nbl_get_bytes(b, 2, 1, &d, &dl) != 0);
    CHECK(nbl_get_bytes(b, 0, 1, &d, &dl) != 0);
    /* corrupt length field */
    uint8_t bad[8] = {0x0a, 0xff, 0xff, 0xff, 0x7f, 1, 2, 3};
    CHECK(nbl_get_bytes(bad, sizeof(bad), 1, &d, &dl) != 0);
}

static void test_ws(void)
{
    uint8_t msg[256];
    nbl_ws_t st;
    nbl_ws_init(&st, msg, sizeof(msg));
    nbl_ws_event_t ev;

    /* nbl_ws_build() is only checked for success here. The parser is fed an unmasked
       frame, as a server sends it. */
    const char *txt = "hello world";
    uint8_t f[64];
    int fl = nbl_ws_build(0x2, (const uint8_t *)txt, strlen(txt), NULL, f, sizeof(f));
    CHECK(fl > 0);

    uint8_t sf[64];
    sf[0] = 0x82;
    sf[1] = (uint8_t)strlen(txt);
    memcpy(sf + 2, txt, strlen(txt));
    int n = nbl_ws_next(&st, sf, 2 + strlen(txt), &ev);
    CHECK(n == (int)(2 + strlen(txt)) && ev.type == NBL_WS_DATA && ev.len == strlen(txt) &&
          memcmp(ev.data, txt, ev.len) == 0);

    /* byte-wise delivery: feed a growing prefix until the parser completes the frame */
    nbl_ws_init(&st, msg, sizeof(msg));
    int got = 0;
    for (size_t i = 1; i <= 2 + strlen(txt) && !got; i++) {
        int r = nbl_ws_next(&st, sf, i, &ev);
        if (r < 0) {
            break;
        }
        if (r == (int)(2 + strlen(txt)) && ev.type == NBL_WS_DATA) {
            got = 1;
        }
    }
    CHECK(got);

    /* fragmentation: two frames, the first one with FIN=0 */
    nbl_ws_init(&st, msg, sizeof(msg));
    uint8_t f1[16], f2[16];
    f1[0] = 0x02; /* FIN=0, opcode 2 (binary) */
    f1[1] = 3;
    memcpy(f1 + 2, "abc", 3);
    f2[0] = 0x80; /* FIN=1, opcode 0 (continuation) */
    f2[1] = 3;
    memcpy(f2 + 2, "def", 3);
    n = nbl_ws_next(&st, f1, 5, &ev);
    CHECK(n == 5 && ev.type == NBL_WS_NEED_MORE);
    uint8_t comb[32];
    memcpy(comb, f2, 5);
    n = nbl_ws_next(&st, comb, 5, &ev);
    CHECK(n == 5 && ev.type == NBL_WS_DATA && ev.len == 6 && memcmp(ev.data, "abcdef", 6) == 0);

    /* ping: answering with PONG is up to the caller, the parser only reports PING */
    nbl_ws_init(&st, msg, sizeof(msg));
    uint8_t ping[4] = {0x89, 0x02, 'h', 'i'};
    n = nbl_ws_next(&st, ping, 4, &ev);
    CHECK(n == 4 && ev.type == NBL_WS_PING && ev.len == 2);

    /* close */
    nbl_ws_init(&st, msg, sizeof(msg));
    uint8_t cl[2] = {0x88, 0x00};
    n = nbl_ws_next(&st, cl, 2, &ev);
    CHECK(n == 2 && ev.type == NBL_WS_CLOSE);

    /* a message larger than the reassembly buffer is rejected */
    nbl_ws_init(&st, msg, 4);
    uint8_t big[8] = {0x82, 6, '1', '2', '3', '4', '5', '6'};
    n = nbl_ws_next(&st, big, 8, &ev);
    CHECK(n < 0);

    /* 16-bit extended payload length */
    nbl_ws_init(&st, msg, sizeof(msg));
    size_t L = 200;
    uint8_t *bf = malloc(4 + L);
    bf[0] = 0x82;
    bf[1] = 126;
    bf[2] = (uint8_t)(L >> 8);
    bf[3] = (uint8_t)L;
    memset(bf + 4, 'x', L);
    n = nbl_ws_next(&st, bf, 4 + L, &ev);
    CHECK(n == (int)(4 + L) && ev.type == NBL_WS_DATA && ev.len == L);
    free(bf);

    /* reserved opcode */
    nbl_ws_init(&st, msg, sizeof(msg));
    uint8_t bad[3] = {0x83, 0x00, 0};
    n = nbl_ws_next(&st, bad, 2, &ev);
    CHECK(n < 0);
}

static void test_relay(void)
{
    uint8_t out[256];
    uint8_t id[NBL_RELAY_ID_LEN];
    memset(id, 'A', sizeof(id));
    uint8_t sig[32];
    memset(sig, 0x5a, sizeof(sig));

    /* auth: [1][6][magic 2112A442][peer ID 36][1 = HMAC-SHA256][signature 32][payload] */
    int n = nbl_relay_build_auth(out, sizeof(out), id, sig, "1234567890");
    CHECK(n > 0);
    CHECK(out[0] == 1 && out[1] == 6);
    CHECK(memcmp(out + 2, "\x21\x12\xA4\x42", 4) == 0);
    CHECK(memcmp(out + 6, id, 36) == 0);
    CHECK(out[42] == 1);
    CHECK(memcmp(out + 43, sig, 32) == 0);
    CHECK(memcmp(out + 75, "1234567890", 10) == 0);

    nbl_relay_msg_t m;
    uint8_t wg[10] = {4, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    n = nbl_relay_build_transport(out, sizeof(out), id, wg, sizeof(wg));
    CHECK(n == 2 + 36 + 10);
    CHECK(nbl_relay_parse(out, n, &m) == 0);
    CHECK(m.type == NBL_R_TRANSPORT && memcmp(m.id, id, 36) == 0 && m.payload_len == 10);
    CHECK(memcmp(m.payload, wg, 10) == 0);

    /* health check */
    uint8_t hc[2] = {1, 5};
    CHECK(nbl_relay_parse(hc, 2, &m) == 0 && m.type == NBL_R_HEALTH);
    /* auth response */
    uint8_t ar[16] = {1, 7, 'r', 'e', 'l', 's', ':', '/', '/', 'x'};
    CHECK(nbl_relay_parse(ar, 10, &m) == 0 && m.type == NBL_R_AUTH_RESP && m.payload_len == 8);
    /* malformed */
    uint8_t b1[1] = {1};
    CHECK(nbl_relay_parse(b1, 1, &m) < 0);
    uint8_t b2[4] = {2, 3, 0, 0}; /* wrong protocol version */
    CHECK(nbl_relay_parse(b2, 4, &m) < 0);
    uint8_t b3[3] = {1, 3, 0}; /* transport message without peer ID */
    CHECK(nbl_relay_parse(b3, 3, &m) < 0);
    /* payload larger than the output buffer (and than NBL_R_MAX_MSG) */
    CHECK(nbl_relay_build_transport(out, sizeof(out), id, wg, NBL_R_MAX_MSG) < 0);
}

static void test_grpc(void)
{
    nbl_grpc_rx_t st;
    nbl_grpc_rx_init(&st, 1024);

    static uint8_t got[4096];

    /* round trip: two messages, the second one empty, fed one byte at a time */
    const char *a = "message one";
    const char *b2 = "";
    uint8_t buf[64];
    int n1 = nbl_grpc_frame(buf, sizeof(buf), (const uint8_t *)a, strlen(a));
    int n2 = nbl_grpc_frame(buf + n1, sizeof(buf) - n1, (const uint8_t *)b2, 0);
    CHECK(n1 > 0 && n2 == 5);

    struct col col = {got, 0, 0};

    for (int i = 0; i < n1 + n2; i++) {
        int rc = nbl_grpc_rx_feed(&st, test_collect_msg, &col, buf + i, 1);
        CHECK(rc == 0);
    }
    CHECK(col.c == 2 && col.n == strlen(a));
    CHECK(memcmp(got, a, strlen(a)) == 0);
    nbl_grpc_rx_free(&st);

    /* compressed flag set: not supported */
    nbl_grpc_rx_init(&st, 1024);
    uint8_t bad[6] = {1, 0, 0, 0, 1, 'x'};
    CHECK(nbl_grpc_rx_feed(&st, NULL, NULL, bad, 6) < 0);
    /* message length above the cap */
    nbl_grpc_rx_init(&st, 4);
    uint8_t big[5] = {0, 0, 0, 1, 0}; /* 256 bytes > cap 4 */
    CHECK(nbl_grpc_rx_feed(&st, NULL, NULL, big, 5) == -2);
    nbl_grpc_rx_free(&st);
}

/* ---------------- inbound firewall (nbl_acl.c) ---------------- */

/* IPv4 address in network byte order */
static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t x[4] = {a, b, c, d};
    uint32_t v;
    memcpy(&v, x, 4);
    return v;
}

#define T_FIN 0x01
#define T_SYN 0x02
#define T_RST 0x04
#define T_ACK 0x10

/* Builds an IPv4 packet in b (NBL_ACL_HDR_MAX bytes) and returns its length. proto 6/17: source
   port a, destination port c and the TCP flags; proto 1: ICMP type a, echo identifier c. */
static size_t mkpkt(uint8_t *b, uint32_t src, uint32_t dst, uint8_t proto, uint16_t a, uint16_t c,
                    uint8_t flags)
{
    memset(b, 0, NBL_ACL_HDR_MAX);
    b[0] = 0x45;
    b[8] = 64;
    b[9] = proto;
    memcpy(b + 12, &src, 4);
    memcpy(b + 16, &dst, 4);
    uint8_t *t = b + 20;
    size_t tl = 8;
    if (proto == 1) {
        t[0] = (uint8_t)a;
        t[4] = (uint8_t)(c >> 8);
        t[5] = (uint8_t)c;
    } else {
        t[0] = (uint8_t)(a >> 8);
        t[1] = (uint8_t)a;
        t[2] = (uint8_t)(c >> 8);
        t[3] = (uint8_t)c;
        if (proto == 6) {
            t[12] = 0x50;
            t[13] = flags;
            tl = 20;
        }
    }
    b[2] = 0;
    b[3] = (uint8_t)(20 + tl);
    return 20 + tl;
}

/* identification, fragment offset (8-byte units) and More Fragments */
static void mkfrag(uint8_t *b, uint16_t id, uint16_t off, bool more)
{
    b[4] = (uint8_t)(id >> 8);
    b[5] = (uint8_t)id;
    b[6] = (uint8_t)((more ? 0x20 : 0) | ((off >> 8) & 0x1f));
    b[7] = (uint8_t)off;
}

static void test_acl_rules(void)
{
    uint32_t m24 = ip4(255, 255, 255, 0), m32 = ip4(255, 255, 255, 255);
    uint32_t in1 = ip4(198, 51, 100, 42);  /* inside the first rule's subnet */
    uint32_t out1 = ip4(198, 51, 101, 42); /* the neighbouring /24 */
    uint32_t host5 = ip4(203, 0, 113, 5);
    uint32_t any = ip4(192, 0, 2, 1); /* matches no source-specific rule */
    /* rules: 198.51.100.0/24 tcp/80; everything from 203.0.113.5; udp/53 from anywhere */
    nbl_acl_rule_t rules[3] = {
        {.src = ip4(198, 51, 100, 0), .mask = m24, .proto = 6, .p0 = 80, .p1 = 80},
        {.src = host5, .mask = m32},
        {.proto = 17, .p0 = 53, .p1 = 53},
    };

    CHECK(nbl_acl_match(rules, 3, in1, 6, true, 80));
    CHECK(!nbl_acl_match(rules, 3, in1, 6, true, 81));
    CHECK(!nbl_acl_match(rules, 3, in1, 17, true, 80)); /* udp != tcp */
    CHECK(!nbl_acl_match(rules, 3, out1, 6, true, 80)); /* wrong subnet */
    CHECK(nbl_acl_match(rules, 3, host5, 1, false, 0)); /* ICMP from 203.0.113.5 */
    CHECK(nbl_acl_match(rules, 3, host5, 6, true, 22));
    CHECK(nbl_acl_match(rules, 3, any, 17, true, 53)); /* udp/53 from anywhere */
    CHECK(!nbl_acl_match(rules, 3, any, 17, true, 54));
    /* packet without port: a port rule cannot match */
    CHECK(!nbl_acl_match(rules, 3, in1, 6, false, 0));
    CHECK(nbl_acl_match(rules, 3, host5, 6, false, 0));
    /* no rules = deny everything */
    CHECK(!nbl_acl_match(NULL, 0, in1, 6, true, 80));
    CHECK(!nbl_acl_match(rules, 0, in1, 6, true, 80));

    /* DROP before ACCEPT, in either order */
    nbl_acl_rule_t dr[2] = {
        {.src = host5, .mask = m32},
        {.src = host5, .mask = m32, .proto = 6, .p0 = 22, .p1 = 22, .action = NBL_ACL_DROP},
    };
    CHECK(!nbl_acl_match(dr, 2, host5, 6, true, 22));
    CHECK(nbl_acl_match(dr, 2, host5, 6, true, 23));
    CHECK(nbl_acl_match(dr, 2, host5, 17, true, 22)); /* the drop rule is TCP only */
    CHECK(nbl_acl_match(dr, 2, host5, 1, false, 0));
    nbl_acl_rule_t rd[2] = {dr[1], dr[0]};
    CHECK(!nbl_acl_match(rd, 2, host5, 6, true, 22));
    CHECK(nbl_acl_match(rd, 2, host5, 6, true, 23));
    CHECK(!nbl_acl_match(&dr[1], 1, host5, 6, true, 23)); /* a lone DROP rule passes nothing */
    /* drop a whole subnet, accept tcp/80 from anywhere */
    nbl_acl_rule_t sub[2] = {
        {.proto = 6, .p0 = 80, .p1 = 80},
        {.src = ip4(198, 51, 100, 0), .mask = m24, .action = NBL_ACL_DROP},
    };
    CHECK(!nbl_acl_match(sub, 2, in1, 6, true, 80));
    CHECK(nbl_acl_match(sub, 2, out1, 6, true, 80));
    CHECK(!nbl_acl_match(sub, 2, out1, 6, true, 81));
    /* unknown action values count as DROP */
    nbl_acl_rule_t odd[2] = {{0}, {.action = 7}};
    CHECK(!nbl_acl_match(odd, 2, any, 6, true, 80));

    /* port ranges are inclusive */
    nbl_acl_rule_t rng = {.proto = 6, .p0 = 8000, .p1 = 8080};
    CHECK(!nbl_acl_match(&rng, 1, any, 6, true, 7999));
    CHECK(nbl_acl_match(&rng, 1, any, 6, true, 8000));
    CHECK(nbl_acl_match(&rng, 1, any, 6, true, 8080));
    CHECK(!nbl_acl_match(&rng, 1, any, 6, true, 8081));
    /* protocol: any vs. specific; ICMP rules have no ports */
    nbl_acl_rule_t anyp = {.src = host5, .mask = m32, .p0 = 443, .p1 = 443};
    CHECK(nbl_acl_match(&anyp, 1, host5, 6, true, 443));
    CHECK(nbl_acl_match(&anyp, 1, host5, 17, true, 443));
    CHECK(!nbl_acl_match(&anyp, 1, host5, 1, false, 0)); /* port rule, ICMP has no port */
    nbl_acl_rule_t icmp = {.proto = 1};
    CHECK(nbl_acl_match(&icmp, 1, any, 1, false, 0));
    CHECK(!nbl_acl_match(&icmp, 1, any, 6, true, 0));
    CHECK(!nbl_acl_match(&icmp, 1, any, 17, true, 7));
}

static void test_acl_filter(void)
{
    uint32_t me = ip4(100, 64, 0, 10), peer = ip4(100, 64, 0, 20), other = ip4(100, 64, 0, 30);
    uint32_t m32 = ip4(255, 255, 255, 255);
    uint8_t b[NBL_ACL_HDR_MAX];
    size_t n;
    nbl_acl_state_t st;
    nbl_acl_init(&st, me);
    nbl_acl_rule_t all = {0};
    nbl_acl_rule_t web = {.src = peer, .mask = m32, .proto = 6, .p0 = 80, .p1 = 80};

    n = mkpkt(b, peer, me, 6, 40000, 80, T_SYN);
    CHECK(nbl_acl_check(&st, &web, 1, b, n, 1));
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, 1)); /* no rules */
    n = mkpkt(b, peer, me, 6, 40000, 81, T_SYN);
    CHECK(!nbl_acl_check(&st, &web, 1, b, n, 1));
    n = mkpkt(b, other, me, 6, 40000, 80, T_SYN);
    CHECK(!nbl_acl_check(&st, &web, 1, b, n, 1));

    /* the destination must be our address, even if a rule accepts everything */
    n = mkpkt(b, peer, ip4(192, 168, 1, 5), 6, 40000, 80, T_SYN);
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    n = mkpkt(b, peer, other, 17, 1000, 2000, 0);
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    n = mkpkt(b, peer, ip4(100, 127, 255, 255), 1, 8, 1, 0); /* broadcast */
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    n = mkpkt(b, peer, me, 1, 8, 1, 0);
    CHECK(nbl_acl_check(&st, &all, 1, b, n, 1));
    /* no address configured: nothing passes */
    nbl_acl_state_t st0;
    nbl_acl_init(&st0, 0);
    n = mkpkt(b, peer, 0, 1, 8, 1, 0);
    CHECK(!nbl_acl_check(&st0, &all, 1, b, n, 1));

    /* malformed headers */
    n = mkpkt(b, peer, me, 17, 1000, 2000, 0);
    CHECK(nbl_acl_check(&st, &all, 1, b, n, 1));
    CHECK(!nbl_acl_check(&st, &all, 1, b, 19, 1));   /* shorter than an IPv4 header */
    CHECK(!nbl_acl_check(&st, &all, 1, NULL, 0, 1));
    b[0] = 0x65; /* IPv6 */
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    b[0] = 0x44; /* header length below 20 */
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    b[0] = 0x4f; /* 60 byte header, longer than the data */
    CHECK(!nbl_acl_check(&st, &all, 1, b, n, 1));
    /* IP options: the ports follow the 24 byte header */
    n = mkpkt(b, peer, me, 6, 40000, 80, T_SYN);
    memmove(b + 24, b + 20, 20);
    memset(b + 20, 1, 4); /* NOP options */
    b[0] = 0x46;
    CHECK(nbl_acl_check(&st, &web, 1, b, n + 4, 1));
    b[27] = 81; /* destination port 81 */
    CHECK(!nbl_acl_check(&st, &web, 1, b, n + 4, 1));

    /* TCP/UDP whose ports cannot be read never pass, not even an accept-all rule */
    n = mkpkt(b, peer, me, 6, 40000, 80, T_SYN);
    CHECK(!nbl_acl_check(&st, &all, 1, b, 20 + 19, 1));
    n = mkpkt(b, peer, me, 17, 40000, 80, 0);
    CHECK(!nbl_acl_check(&st, &all, 1, b, 20 + 7, 1));
    /* ICMP needs no ports: a truncated ICMP header still matches an ICMP rule */
    n = mkpkt(b, peer, me, 1, 8, 1, 0);
    CHECK(nbl_acl_check(&st, &all, 1, b, 20 + 4, 1));
    /* other protocols follow the rules: an any-protocol rule accepts, a TCP rule does not */
    n = mkpkt(b, peer, me, 47, 0, 0, 0); /* GRE */
    CHECK(nbl_acl_check(&st, &all, 1, b, n, 1));
    CHECK(!nbl_acl_check(&st, &web, 1, b, n, 1));

    /* DROP rules win over ACCEPT rules */
    nbl_acl_rule_t dr[2] = {all, {.src = peer, .mask = m32, .action = NBL_ACL_DROP}};
    n = mkpkt(b, peer, me, 6, 40000, 80, T_SYN);
    CHECK(!nbl_acl_check(&st, dr, 2, b, n, 1));
    n = mkpkt(b, other, me, 6, 40000, 80, T_SYN);
    CHECK(nbl_acl_check(&st, dr, 2, b, n, 1));
}

static void test_acl_conntrack(void)
{
    uint32_t me = ip4(100, 64, 0, 10), peer = ip4(100, 64, 0, 20), other = ip4(100, 64, 0, 30);
    uint32_t lan = ip4(192, 168, 1, 5), m32 = ip4(255, 255, 255, 255);
    uint8_t b[NBL_ACL_HDR_MAX];
    size_t n;
    nbl_acl_state_t st;
    nbl_acl_init(&st, me);
    uint32_t t = 1000;

    /* TCP: SYN out, the SYN-ACK passes without any rule */
    n = mkpkt(b, me, peer, 6, 40000, 443, T_SYN);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, peer, me, 6, 443, 40000, T_SYN | T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t));
    /* unrelated inbound: other local port, remote port, peer or protocol */
    n = mkpkt(b, peer, me, 6, 443, 40001, T_ACK);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 6, 444, 40000, T_ACK);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, other, me, 6, 443, 40000, T_ACK);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 17, 443, 40000, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    /* a reply must still be addressed to us */
    n = mkpkt(b, peer, lan, 6, 443, 40000, T_ACK);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    /* new connection from the peer to us: up to the rules */
    n = mkpkt(b, peer, me, 6, 50000, 22, T_SYN);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));

    /* only packets from our address are tracked (no forwarded traffic) */
    n = mkpkt(b, lan, peer, 6, 40002, 443, T_SYN);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, peer, me, 6, 443, 40002, T_SYN | T_ACK);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    /* trailing fragments and truncated headers are not tracked */
    n = mkpkt(b, me, peer, 17, 40003, 53, 0);
    mkfrag(b, 1, 10, false);
    nbl_acl_track(&st, b, n, t);
    nbl_acl_track(&st, b, 20 + 7, t);
    n = mkpkt(b, me, peer, 17, 40003, 53, 0);
    nbl_acl_track(&st, b, 20 + 7, t);
    n = mkpkt(b, peer, me, 17, 53, 40003, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));

    /* UDP */
    n = mkpkt(b, me, peer, 17, 5353, 53, 0);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, peer, me, 17, 53, 5353, 0);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 17, 53, 5354, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 17, 54, 5353, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));

    /* ICMP echo: the reply with the same identifier passes */
    n = mkpkt(b, me, peer, 1, 8, 7, 0);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, peer, me, 1, 0, 7, 0);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 1, 0, 8, 0); /* other identifier */
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, other, me, 1, 0, 7, 0); /* other host */
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 1, 8, 7, 0); /* an echo request is no reply */
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, peer, me, 1, 3, 7, 0); /* destination unreachable */
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    /* answering a ping (echo reply out) opens nothing */
    n = mkpkt(b, me, other, 1, 0, 9, 0);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, other, me, 1, 0, 9, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));
    n = mkpkt(b, other, me, 1, 8, 9, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t));

    /* replies to tracked connections pass before the DROP rules are consulted */
    nbl_acl_rule_t deny = {.src = peer, .mask = m32, .action = NBL_ACL_DROP};
    n = mkpkt(b, peer, me, 17, 53, 5353, 0);
    CHECK(nbl_acl_check(&st, &deny, 1, b, n, t + 1));
    n = mkpkt(b, peer, me, 17, 53, 5000, 0);
    CHECK(!nbl_acl_check(&st, &deny, 1, b, n, t + 1));

    /* a new address forgets all connections */
    nbl_acl_init(&st, other);
    n = mkpkt(b, peer, me, 17, 53, 5353, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t + 2));
    n = mkpkt(b, peer, other, 17, 53, 5353, 0);
    CHECK(!nbl_acl_check(&st, NULL, 0, b, n, t + 2));
}

static void test_acl_timeouts(void)
{
    uint32_t me = ip4(100, 64, 0, 10), peer = ip4(100, 64, 0, 20);
    uint8_t b[NBL_ACL_HDR_MAX], r[NBL_ACL_HDR_MAX];
    size_t n, rn;
    nbl_acl_state_t st;
    nbl_acl_init(&st, me);
    uint32_t t = 1000;

    /* UDP: 120 s idle; replies refresh the entry */
    n = mkpkt(b, me, peer, 17, 5000, 53, 0);
    rn = mkpkt(r, peer, me, 17, 53, 5000, 0);
    nbl_acl_track(&st, b, n, t);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 119));
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 238));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 358));
    /* outbound packets refresh it too */
    t = 5000;
    nbl_acl_track(&st, b, n, t);
    nbl_acl_track(&st, b, n, t + 100);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 219));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 339));

    /* ICMP echo: 30 s */
    t = 10000;
    n = mkpkt(b, me, peer, 1, 8, 77, 0);
    rn = mkpkt(r, peer, me, 1, 0, 77, 0);
    nbl_acl_track(&st, b, n, t);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 29));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 59));

    /* TCP: 2 h */
    t = 20000;
    n = mkpkt(b, me, peer, 6, 41000, 80, T_SYN);
    rn = mkpkt(r, peer, me, 6, 80, 41000, T_ACK);
    nbl_acl_track(&st, b, n, t);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 7199));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 7199 + 7200));

    /* TCP: 10 s after a RST */
    t = 40000;
    n = mkpkt(b, me, peer, 6, 41001, 80, T_SYN);
    nbl_acl_track(&st, b, n, t);
    rn = mkpkt(r, peer, me, 6, 80, 41001, T_RST | T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t));
    rn = mkpkt(r, peer, me, 6, 80, 41001, T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 9));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 19));
    /* ...also after our own RST */
    n = mkpkt(b, me, peer, 6, 41002, 80, T_SYN);
    nbl_acl_track(&st, b, n, t + 20);
    n = mkpkt(b, me, peer, 6, 41002, 80, T_RST);
    nbl_acl_track(&st, b, n, t + 120);
    rn = mkpkt(r, peer, me, 6, 80, 41002, T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 129));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 139));

    /* TCP: a FIN in one direction keeps the long timeout, FINs in both directions end it */
    t = 50000;
    n = mkpkt(b, me, peer, 6, 41003, 80, T_SYN);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, me, peer, 6, 41003, 80, T_FIN | T_ACK);
    nbl_acl_track(&st, b, n, t);
    rn = mkpkt(r, peer, me, 6, 80, 41003, T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 100));
    rn = mkpkt(r, peer, me, 6, 80, 41003, T_FIN | T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 100));
    rn = mkpkt(r, peer, me, 6, 80, 41003, T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 109));
    /* a new SYN on the closed port pair starts a fresh connection with the long timeout */
    n = mkpkt(b, me, peer, 6, 41003, 80, T_SYN);
    nbl_acl_track(&st, b, n, t + 110);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 210));
    /* the same close sequence without the new SYN expires 10 s after the last packet */
    t += 300;
    n = mkpkt(b, me, peer, 6, 41004, 80, T_SYN);
    nbl_acl_track(&st, b, n, t);
    rn = mkpkt(r, peer, me, 6, 80, 41004, T_FIN | T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 1));
    n = mkpkt(b, me, peer, 6, 41004, 80, T_FIN | T_ACK);
    nbl_acl_track(&st, b, n, t + 2);
    rn = mkpkt(r, peer, me, 6, 80, 41004, T_ACK);
    CHECK(nbl_acl_check(&st, NULL, 0, r, rn, t + 11));
    CHECK(!nbl_acl_check(&st, NULL, 0, r, rn, t + 21));
}

static void test_acl_lru(void)
{
    uint32_t me = ip4(100, 64, 0, 10), peer = ip4(100, 64, 0, 20);
    uint8_t b[NBL_ACL_HDR_MAX];
    size_t n;
    nbl_acl_state_t st;
    nbl_acl_init(&st, me);
    const int N = CONFIG_NBL_CT_ENTRIES;
    uint32_t t = 100;

    /* fill the table, flow i at t + i */
    for (int i = 0; i < N; i++) {
        n = mkpkt(b, me, peer, 17, (uint16_t)(10000 + i), 53, 0);
        nbl_acl_track(&st, b, n, t + (uint32_t)i);
    }
    /* flow 0 is used again, so flow 1 is now the least recently used one */
    n = mkpkt(b, me, peer, 17, 10000, 53, 0);
    nbl_acl_track(&st, b, n, t + (uint32_t)N);
    n = mkpkt(b, me, peer, 17, (uint16_t)(10000 + N), 53, 0);
    nbl_acl_track(&st, b, n, t + (uint32_t)N + 1);
    int passed = 0;
    for (int i = 0; i <= N; i++) {
        n = mkpkt(b, peer, me, 17, 53, (uint16_t)(10000 + i), 0);
        bool ok = nbl_acl_check(&st, NULL, 0, b, n, t + (uint32_t)N + 2);
        CHECK(ok == (i != 1));
        passed += ok;
    }
    CHECK(passed == N);

    /* expired entries are reused before live ones are replaced */
    nbl_acl_init(&st, me);
    n = mkpkt(b, me, peer, 1, 8, 1, 0); /* ICMP: 30 s */
    nbl_acl_track(&st, b, n, t);
    for (int i = 1; i < N; i++) {
        n = mkpkt(b, me, peer, 17, (uint16_t)(20000 + i), 53, 0);
        nbl_acl_track(&st, b, n, t);
    }
    n = mkpkt(b, me, peer, 17, 30000, 53, 0);
    nbl_acl_track(&st, b, n, t + 31);
    passed = 0;
    for (int i = 1; i < N; i++) {
        n = mkpkt(b, peer, me, 17, 53, (uint16_t)(20000 + i), 0);
        passed += nbl_acl_check(&st, NULL, 0, b, n, t + 32);
    }
    CHECK(passed == N - 1);
    n = mkpkt(b, peer, me, 17, 53, 30000, 0);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 32));
}

static void test_acl_fragments(void)
{
    uint32_t me = ip4(100, 64, 0, 10), peer = ip4(100, 64, 0, 20), other = ip4(100, 64, 0, 30);
    uint32_t m32 = ip4(255, 255, 255, 255);
    uint8_t b[NBL_ACL_HDR_MAX];
    size_t n;
    nbl_acl_state_t st;
    nbl_acl_init(&st, me);
    nbl_acl_rule_t udp5000 = {.src = peer, .mask = m32, .proto = 17, .p0 = 5000, .p1 = 5000};
    uint32_t t = 1000;

    /* the first fragment is checked like an unfragmented packet */
    n = mkpkt(b, peer, me, 17, 40000, 5000, 0);
    mkfrag(b, 0x1234, 0, true);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t));
    /* the trailing fragments of that datagram inherit its verdict, in any order */
    n = mkpkt(b, peer, me, 17, 0, 0, 0);
    mkfrag(b, 0x1234, 370, false);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    mkfrag(b, 0x1234, 185, true);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 1)); /* no rule needed */
    /* ...but not those of another datagram, source or protocol */
    mkfrag(b, 0x1235, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    n = mkpkt(b, other, me, 17, 0, 0, 0);
    mkfrag(b, 0x1234, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    n = mkpkt(b, peer, me, 6, 0, 0, 0);
    mkfrag(b, 0x1234, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    /* or for another destination */
    n = mkpkt(b, peer, other, 17, 0, 0, 0);
    mkfrag(b, 0x1234, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t + 1));
    /* the verdict expires 30 s after the first fragment */
    n = mkpkt(b, peer, me, 17, 0, 0, 0);
    mkfrag(b, 0x1234, 185, false);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t + 29));
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t + 30));

    /* trailing fragments of a dropped datagram, or of an unknown one */
    t += 100; /* the clock is monotonic */
    n = mkpkt(b, peer, me, 17, 40000, 5001, 0);
    mkfrag(b, 0x2000, 0, true);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    mkfrag(b, 0x2000, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    mkfrag(b, 0x3000, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    /* a dropped re-sent first fragment revokes the earlier verdict */
    n = mkpkt(b, peer, me, 17, 40000, 5000, 0);
    mkfrag(b, 0x4000, 0, true);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t));
    n = mkpkt(b, peer, me, 17, 40000, 5001, 0);
    mkfrag(b, 0x4000, 0, true);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    mkfrag(b, 0x4000, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    /* a first fragment too short for the UDP header is dropped, and so is the rest */
    n = mkpkt(b, peer, me, 17, 40000, 5000, 0);
    mkfrag(b, 0x5000, 0, true);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, 20 + 4, t));
    mkfrag(b, 0x5000, 1, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));
    /* an unfragmented packet leaves no verdict behind */
    n = mkpkt(b, peer, me, 17, 40000, 5000, 0);
    mkfrag(b, 0x7000, 0, false);
    CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t));
    mkfrag(b, 0x7000, 185, false);
    CHECK(!nbl_acl_check(&st, &udp5000, 1, b, n, t));

    /* fragmented reply to a tracked connection */
    n = mkpkt(b, me, peer, 17, 6000, 7000, 0);
    nbl_acl_track(&st, b, n, t);
    n = mkpkt(b, peer, me, 17, 7000, 6000, 0);
    mkfrag(b, 0x6000, 0, true);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 1));
    mkfrag(b, 0x6000, 185, false);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 1));
    /* fragmented ping reply */
    n = mkpkt(b, me, peer, 1, 8, 99, 0);
    nbl_acl_track(&st, b, n, t + 1);
    n = mkpkt(b, peer, me, 1, 0, 99, 0);
    mkfrag(b, 0x6001, 0, true);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 2));
    mkfrag(b, 0x6001, 185, false);
    CHECK(nbl_acl_check(&st, NULL, 0, b, n, t + 2));

    /* the cache holds the newest NBL_ACL_FRAG_ENTRIES datagrams */
    nbl_acl_init(&st, me);
    for (int i = 0; i <= NBL_ACL_FRAG_ENTRIES; i++) {
        n = mkpkt(b, peer, me, 17, 40000, 5000, 0);
        mkfrag(b, (uint16_t)(0x8000 + i), 0, true);
        CHECK(nbl_acl_check(&st, &udp5000, 1, b, n, t + (uint32_t)i));
    }
    int passed = 0;
    for (int i = 0; i <= NBL_ACL_FRAG_ENTRIES; i++) {
        mkfrag(b, (uint16_t)(0x8000 + i), 185, false);
        bool ok = nbl_acl_check(&st, &udp5000, 1, b, n, t + NBL_ACL_FRAG_ENTRIES + 1);
        CHECK(ok == (i != 0));
        passed += ok;
    }
    CHECK(passed == NBL_ACL_FRAG_ENTRIES);
}

int main(void)
{
    test_wire();
    test_ws();
    test_relay();
    test_grpc();
    test_acl_rules();
    test_acl_filter();
    test_acl_conntrack();
    test_acl_timeouts();
    test_acl_lru();
    test_acl_fragments();
    if (fails) {
        printf("test_units: %d of %d checks FAILED\n", fails, checks);
        return 1;
    }
    printf("test_units: all %d checks passed\n", checks);
    return 0;
}
