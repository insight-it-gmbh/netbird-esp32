// Host unit tests for nbl_netmap.c: firewall rule conversion (fail closed, DROP rules, truncation)
// and the robustness of the SyncResponse decoder (routing peers, many relays, IPv6 prefixes, long
// values). The messages are built with the nbl_wire.h writer and decoded through the real nanopb
// code. Plain C11, no ESP-IDF needed.
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nbl_acl.h"
#include "nbl_netmap.h"
#include "nbl_wire.h"

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

/* ---------------- protobuf writer ---------------- */

typedef struct {
    uint8_t b[16384];
    size_t n;
} buf_t;

static void w_bytes(buf_t *o, int field, const void *d, size_t l)
{
    o->n = nbl_put_bytes(o->b, o->n, field, d, l);
}

static void w_str(buf_t *o, int field, const char *s)
{
    w_bytes(o, field, s, strlen(s));
}

static void w_int(buf_t *o, int field, uint64_t v)
{
    o->n = nbl_put_int(o->b, o->n, field, v);
}

static void w_msg(buf_t *o, int field, const buf_t *m)
{
    w_bytes(o, field, m->b, m->n);
}

static const char *KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
static const char *KEY_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
static const char *KEY_C = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
static const char *KEY_OWN = "OwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnA=";

/* FirewallRule (management.proto): PeerIP=1 Direction=2 Action=3 Protocol=4 Port=5 PortInfo=6
 * (port=1 | range=2 {start=1 end=2}) customProtocol=8 sourcePrefixes=9 */
enum { ALL = 1, TCP = 2, UDP = 3, ICMP = 4, CUSTOM = 5 };
enum { IN = 0, OUT = 1 };
enum { ACCEPT = 0, DROP = 1 };

typedef struct {
    const char *peer_ip; /* NULL = absent */
    int dir, action, proto;
    const char *port;    /* NULL = absent */
    int pi;              /* 0 none, 1 port, 2 range, 3 empty PortInfo */
    uint32_t pi_a, pi_b;
    uint32_t custom;
    const uint8_t *src[6];
    size_t src_len[6];
} fw_t;

static void w_rule(buf_t *map, const fw_t *r)
{
    buf_t m = {.n = 0};
    if (r->peer_ip) {
        w_str(&m, 1, r->peer_ip);
    }
    if (r->dir) {
        w_int(&m, 2, (uint64_t)r->dir);
    }
    if (r->action) {
        w_int(&m, 3, (uint64_t)r->action);
    }
    if (r->proto) {
        w_int(&m, 4, (uint64_t)r->proto);
    }
    if (r->port) {
        w_str(&m, 5, r->port);
    }
    if (r->pi) {
        buf_t pi = {.n = 0};
        if (r->pi == 1) {
            w_int(&pi, 1, r->pi_a);
        } else if (r->pi == 2) {
            buf_t rg = {.n = 0};
            if (r->pi_a) {
                w_int(&rg, 1, r->pi_a);
            }
            if (r->pi_b) {
                w_int(&rg, 2, r->pi_b);
            }
            w_msg(&pi, 2, &rg);
        }
        w_msg(&m, 6, &pi);
    }
    if (r->custom) {
        w_int(&m, 8, r->custom);
    }
    for (int i = 0; i < 6 && r->src[i]; i++) {
        w_bytes(&m, 9, r->src[i], r->src_len[i]);
    }
    w_msg(map, 8, &m);
}

/* RemotePeerConfig: wgPubKey=1 allowedIps=2 (repeated) fqdn=4 agentVersion=5 */
static void w_peer(buf_t *map, const char *key, const char *const *ips)
{
    buf_t m = {.n = 0};
    if (key) {
        w_str(&m, 1, key);
    }
    for (int i = 0; ips && ips[i]; i++) {
        w_str(&m, 2, ips[i]);
    }
    w_str(&m, 4, "a-rather-long-fully-qualified-name.of-a-routing-peer.netbird.cloud");
    w_str(&m, 5, "0.80.0");
    w_msg(map, 3, &m);
}

/* SyncResponse: netbirdConfig=1, NetworkMap=5 {Serial=1 peerConfig=2 {address=1 mtu=7}
 * remotePeers=3 FirewallRules=8} */
static void w_sync(buf_t *out, const buf_t *map)
{
    out->n = 0;
    w_msg(out, 5, map);
}

static void w_map_head(buf_t *map, uint64_t serial, const char *address)
{
    map->n = 0;
    w_int(map, 1, serial);
    buf_t pc = {.n = 0};
    w_str(&pc, 1, address);
    w_int(&pc, 7, 1280);
    w_msg(map, 2, &pc);
}

/* ---------------- decoder harness ---------------- */

static nbl_nm_peer_t g_peers[4];
static nbl_acl_rule_t g_rules[8];
static nbl_netmap_t g_nm;

static int decode(const buf_t *msg, int max_rules)
{
    /* NBL_SEED_DIR=dir: also write every message as a seed for fuzz_wire */
    static int seeds;
    const char *dir = getenv("NBL_SEED_DIR");
    if (dir) {
        char path[512];
        snprintf(path, sizeof(path), "%s/sync_%03d", dir, seeds++);
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(msg->b, 1, msg->n, f);
            fclose(f);
        }
    }
    memset(&g_nm, 0, sizeof(g_nm));
    memset(g_rules, 0xee, sizeof(g_rules));
    g_nm.peers = g_peers;
    g_nm.max_peers = 4;
    g_nm.rules = g_rules;
    g_nm.max_rules = max_rules;
    g_nm.own_key = KEY_OWN;
    return nbl_netmap_decode(msg->b, msg->n, &g_nm);
}

/* Decodes a map with just this rule. Returns the number of ACL entries. */
static int one_rule(const fw_t *r)
{
    static buf_t map, msg;
    w_map_head(&map, 1, "100.64.0.1/16");
    w_rule(&map, r);
    w_sync(&msg, &map);
    CHECK(decode(&msg, 8) == 0);
    CHECK(g_nm.fw_total == 1);
    return g_nm.n_rules;
}

static uint32_t ip(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a.s_addr;
}

static bool rule_is(int i, const char *src, unsigned pfx, uint8_t proto, uint16_t p0, uint16_t p1, uint8_t action)
{
    const nbl_acl_rule_t *r = &g_rules[i];
    uint32_t mask = pfx ? htonl(0xffffffffu << (32 - pfx)) : 0;
    return r->src == ip(src) && r->mask == mask && r->proto == proto && r->p0 == p0 && r->p1 == p1 && r->action == action;
}

/* ---------------- tests ---------------- */

static void test_parsers(void)
{
    uint32_t a;
    int pfx;
    CHECK(nbl_nm_parse_ip4("100.64.0.5", &a, &pfx) && a == ip("100.64.0.5") && pfx == -1);
    CHECK(nbl_nm_parse_ip4("0.0.0.0/0", &a, &pfx) && a == 0 && pfx == 0);
    CHECK(nbl_nm_parse_ip4("255.255.255.255/32", &a, &pfx) && a == 0xffffffffu && pfx == 32);
    CHECK(nbl_nm_parse_ip4("10.0.0.0/8", &a, &pfx) && pfx == 8);
    const char *bad[] = {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.04", "1.2.3.4/", "1.2.3.4/33",
                         "1.2.3.4/08", "1.2.3.4/-1", " 1.2.3.4", "1.2.3.4 ", "1..3.4", "+1.2.3.4", "1.2.3.4/32x",
                         "0x1.2.3.4", "1.2.3.4/1/2", "fd00::1", "1.2.3.4\n", "1000.2.3.4", "1.2.3.4/100"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(!nbl_nm_parse_ip4(bad[i], &a, &pfx));
    }
    for (unsigned p = 0; p <= 32; p++) {
        CHECK(nbl_nm_mask4(p) == (p ? htonl(0xffffffffu << (32 - p)) : 0));
    }
}

static void test_rule_basic(void)
{
    /* TCP 80 from one peer */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .proto = TCP, .port = "80"}) == 1);
    CHECK(rule_is(0, "100.64.0.5", 32, 6, 80, 80, NBL_ACL_ACCEPT));
    /* DROP is converted with its action */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .action = DROP, .proto = UDP, .port = "53"}) == 1);
    CHECK(rule_is(0, "100.64.0.5", 32, 17, 53, 53, NBL_ACL_DROP) && !g_nm.deny_lost);
    /* outbound rules are not needed (connection tracking): skipped */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .dir = OUT, .proto = ALL}) == 0);
    CHECK(g_nm.fw_skipped == 1 && g_nm.fw_malformed == 0);
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .dir = OUT, .action = DROP, .proto = ALL}) == 0 && !g_nm.deny_lost);
    /* 0.0.0.0 = every peer; CIDR sources */
    CHECK(one_rule(&(fw_t){.peer_ip = "0.0.0.0", .proto = ICMP}) == 1 && rule_is(0, "0.0.0.0", 0, 1, 0, 0, 0));
    CHECK(one_rule(&(fw_t){.peer_ip = "10.1.0.0/16", .proto = ALL}) == 1 && rule_is(0, "10.1.0.0", 16, 0, 0, 0, 0));
    CHECK(one_rule(&(fw_t){.peer_ip = "10.1.2.3/0", .proto = ALL}) == 1 && g_rules[0].mask == 0);
    /* IPv6 sources never match an IPv4 packet: not applicable, also for DROP */
    CHECK(one_rule(&(fw_t){.peer_ip = "fd00::5", .proto = ALL}) == 0 && g_nm.fw_skipped == 1);
    CHECK(one_rule(&(fw_t){.peer_ip = "::", .action = DROP, .proto = ALL}) == 0 && !g_nm.deny_lost);
    /* custom protocol (GRE) */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .proto = CUSTOM, .custom = 47}) == 1);
    CHECK(rule_is(0, "100.64.0.5", 32, 47, 0, 0, 0));
    /* ALL with a port: only TCP/UDP packets to that port match */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .proto = ALL, .port = "22"}) == 1);
    CHECK(rule_is(0, "100.64.0.5", 32, 0, 22, 22, 0));
}

static void test_rule_ports(void)
{
    const char *src = "100.64.0.9";
    /* PortInfo.port, PortInfo.range */
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 1, .pi_a = 443}) == 1 && rule_is(0, src, 32, 6, 443, 443, 0));
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = UDP, .pi = 2, .pi_a = 1000, .pi_b = 2000}) == 1);
    CHECK(rule_is(0, src, 32, 17, 1000, 2000, 0));
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 2, .pi_a = 1, .pi_b = 65535}) == 1);
    CHECK(rule_is(0, src, 32, 6, 1, 65535, 0));
    /* range 0-0 is what the server sends for "all ports" */
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 2}) == 1 && rule_is(0, src, 32, 6, 0, 0, 0));
    /* empty PortInfo (port 0, no selection) falls back to the Port string */
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 1, .pi_a = 0, .port = "8080"}) == 1);
    CHECK(rule_is(0, src, 32, 6, 8080, 8080, 0));
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 3, .port = "25"}) == 1 && rule_is(0, src, 32, 6, 25, 25, 0));
    /* PortInfo wins over the Port string */
    CHECK(one_rule(&(fw_t){.peer_ip = src, .proto = TCP, .pi = 1, .pi_a = 22, .port = "80"}) == 1);
    CHECK(rule_is(0, src, 32, 6, 22, 22, 0));
    /* fail closed: malformed or out-of-range ports skip the rule, never "any port" */
    const fw_t bad[] = {
        {.peer_ip = src, .proto = TCP, .pi = 1, .pi_a = 65536},
        {.peer_ip = src, .proto = TCP, .pi = 1, .pi_a = 0xffffffffu},
        {.peer_ip = src, .proto = TCP, .pi = 2, .pi_a = 2000, .pi_b = 1000},
        {.peer_ip = src, .proto = TCP, .pi = 2, .pi_a = 0, .pi_b = 100},
        {.peer_ip = src, .proto = TCP, .pi = 2, .pi_a = 100, .pi_b = 0},
        {.peer_ip = src, .proto = TCP, .pi = 2, .pi_a = 1, .pi_b = 70000},
        {.peer_ip = src, .proto = TCP, .port = "0"},
        {.peer_ip = src, .proto = TCP, .port = "65536"},
        {.peer_ip = src, .proto = TCP, .port = "80a"},
        {.peer_ip = src, .proto = TCP, .port = "+80"},
        {.peer_ip = src, .proto = TCP, .port = "-1"},
        {.peer_ip = src, .proto = TCP, .port = " 80"},
        {.peer_ip = src, .proto = TCP, .port = "080"},
        {.peer_ip = src, .proto = TCP, .port = "8000-8100"},
        {.peer_ip = src, .proto = TCP, .port = "123456789012345678901234567890"},
        {.peer_ip = src, .proto = ICMP, .port = "80"},             /* ports for a protocol without ports */
        {.peer_ip = src, .proto = CUSTOM, .custom = 47, .pi = 1, .pi_a = 80},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(one_rule(&bad[i]) == 0);
        CHECK(g_nm.fw_malformed == 1 && !g_nm.deny_lost);
    }
}

static void test_rule_malformed(void)
{
    /* sources, protocols, directions and actions that do not parse: skipped, never "any" */
    const fw_t bad[] = {
        {.peer_ip = "", .proto = ALL},
        {.proto = ALL},                                         /* no source at all */
        {.peer_ip = "100.64.0.256", .proto = ALL},
        {.peer_ip = "100.64.0.5/33", .proto = ALL},
        {.peer_ip = "100.64.0.5/", .proto = ALL},
        {.peer_ip = "any", .proto = ALL},
        {.peer_ip = "100.64.0.5", .proto = 0},                  /* UNKNOWN */
        {.peer_ip = "100.64.0.5", .proto = 6},                  /* NETBIRD_SSH or newer: unknown */
        {.peer_ip = "100.64.0.5", .proto = CUSTOM},             /* customProtocol 0 would be "any" */
        {.peer_ip = "100.64.0.5", .proto = CUSTOM, .custom = 256},
        {.peer_ip = "100.64.0.5", .dir = 2, .proto = ALL},
        {.peer_ip = "1.2.3.4.example.com.and.something.much.longer.than.48.characters", .proto = ALL},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(one_rule(&bad[i]) == 0);
        CHECK(g_nm.fw_malformed == 1 && !g_nm.deny_lost);
    }
    /* an action we do not know may have been a deny */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .action = 2, .proto = ALL}) == 0 && g_nm.deny_lost);
    /* a malformed DROP rule: no ACCEPT rule may stay */
    static buf_t map, msg;
    w_map_head(&map, 1, "100.64.0.1/16");
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.5", .proto = TCP, .port = "80"});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.6", .action = DROP, .proto = TCP, .port = "99999"});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.7", .proto = ALL});
    w_sync(&msg, &map);
    CHECK(decode(&msg, 8) == 0 && g_nm.fw_total == 3 && g_nm.deny_lost && g_nm.n_rules == 0);
    /* an unreadable rule entry (wrong wire type for Direction): treated like a malformed DROP;
     * peers and the rest of the map still decode */
    w_map_head(&map, 1, "100.64.0.1/16");
    w_peer(&map, KEY_A, (const char *const[]){"100.64.0.2/32", NULL});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.5", .proto = ALL});
    const uint8_t broken[] = {0x12, 0x01, 'x'}; /* field 2 (enum) as a string */
    w_bytes(&map, 8, broken, sizeof(broken));
    w_sync(&msg, &map);
    CHECK(decode(&msg, 8) == 0 && g_nm.fw_total == 2 && g_nm.fw_malformed == 1 && g_nm.deny_lost);
    CHECK(g_nm.n_rules == 0 && g_nm.n_peers == 1);
}

static void test_rule_prefixes(void)
{
    static const uint8_t net8[5] = {10, 0, 0, 0, 8}, host[5] = {100, 64, 0, 7, 32}, any4[5] = {0, 0, 0, 0, 0};
    static const uint8_t bad_pfx[5] = {10, 0, 0, 0, 33}, six[6] = {1, 2, 3, 4, 32, 0};
    static const uint8_t v6[17] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 128};
    static const uint8_t v6bad[17] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 129};
    static const uint8_t mapped[17] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 0, 24};
    /* sourcePrefixes supersede PeerIP */
    CHECK(one_rule(&(fw_t){.peer_ip = "100.64.0.5", .proto = TCP, .port = "80", .src = {net8}, .src_len = {5}}) == 1);
    CHECK(rule_is(0, "10.0.0.0", 8, 6, 80, 80, 0));
    CHECK(one_rule(&(fw_t){.proto = ALL, .src = {any4}, .src_len = {5}}) == 1 && g_rules[0].mask == 0);
    /* several sources: one entry each; IPv6 entries are not applicable */
    CHECK(one_rule(&(fw_t){.proto = ALL, .action = DROP, .src = {host, v6, net8}, .src_len = {5, 17, 5}}) == 2);
    CHECK(rule_is(0, "100.64.0.7", 32, 0, 0, 0, NBL_ACL_DROP) && rule_is(1, "10.0.0.0", 8, 0, 0, 0, NBL_ACL_DROP));
    CHECK(one_rule(&(fw_t){.proto = ALL, .action = DROP, .src = {v6}, .src_len = {17}}) == 0);
    CHECK(g_nm.fw_skipped == 1 && !g_nm.deny_lost);
    /* IPv4-mapped IPv6 is an IPv4 prefix (upstream DecodePrefix) */
    CHECK(one_rule(&(fw_t){.proto = ALL, .src = {mapped}, .src_len = {17}}) == 1);
    CHECK(rule_is(0, "192.168.1.0", 24, 0, 0, 0, 0));
    /* invalid entries: the whole rule is skipped */
    const fw_t bad[] = {
        {.proto = ALL, .src = {bad_pfx}, .src_len = {5}},
        {.proto = ALL, .src = {six}, .src_len = {6}},
        {.proto = ALL, .src = {host, six}, .src_len = {5, 4}},
        {.proto = ALL, .src = {v6bad}, .src_len = {17}},
        {.proto = ALL, .src = {host, host, host, host, host}, .src_len = {5, 5, 5, 5, 5}}, /* more than fit */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(one_rule(&bad[i]) == 0 && g_nm.fw_malformed == 1);
    }
}

static void test_rule_truncation(void)
{
    static buf_t map, msg;
    char ipbuf[6][32];
    /* 6 ACCEPT rules, room for 4: truncated, the rest stays */
    w_map_head(&map, 1, "100.64.0.1/16");
    for (int i = 0; i < 6; i++) {
        snprintf(ipbuf[i], sizeof(ipbuf[i]), "100.64.1.%d", i + 1);
        w_rule(&map, &(fw_t){.peer_ip = ipbuf[i], .proto = ALL});
    }
    w_sync(&msg, &map);
    CHECK(decode(&msg, 4) == 0 && g_nm.n_rules == 4 && g_nm.fw_truncated == 2 && !g_nm.deny_lost);
    /* 4 ACCEPT then 2 DROP rules: the denies replace accepts */
    w_map_head(&map, 1, "100.64.0.1/16");
    for (int i = 0; i < 4; i++) {
        w_rule(&map, &(fw_t){.peer_ip = ipbuf[i], .proto = ALL});
    }
    w_rule(&map, &(fw_t){.peer_ip = "100.64.2.1", .action = DROP, .proto = ALL});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.2.2", .action = DROP, .proto = ALL});
    w_sync(&msg, &map);
    CHECK(decode(&msg, 4) == 0 && g_nm.n_rules == 4 && g_nm.fw_truncated == 2 && !g_nm.deny_lost);
    int drops = 0;
    for (int i = 0; i < g_nm.n_rules; i++) {
        drops += g_rules[i].action == NBL_ACL_DROP;
    }
    CHECK(drops == 2);
    CHECK(!nbl_acl_match(g_rules, (size_t)g_nm.n_rules, ip("100.64.2.1"), 6, true, 80));
    CHECK(nbl_acl_match(g_rules, (size_t)g_nm.n_rules, ip("100.64.1.1"), 6, true, 80));
    /* more DROP rules than fit: fail closed, nothing passes */
    w_map_head(&map, 1, "100.64.0.1/16");
    w_rule(&map, &(fw_t){.peer_ip = "0.0.0.0", .proto = ALL});
    for (int i = 0; i < 5; i++) {
        w_rule(&map, &(fw_t){.peer_ip = ipbuf[i], .action = DROP, .proto = ALL});
    }
    w_sync(&msg, &map);
    CHECK(decode(&msg, 4) == 0 && g_nm.deny_lost && g_nm.n_rules == 0);
}

static void test_peers(void)
{
    static buf_t map, msg;
    w_map_head(&map, 7, "100.64.0.1/16");
    /* a routing peer: own /32 first, then IPv6 and routed networks (also a routed host route) */
    w_peer(&map, KEY_A, (const char *const[]){"100.64.0.2/32", "fd00:1234::2/128", "192.168.10.0/24", "10.0.0.0/8",
                                              "172.16.0.0/12", "192.168.10.7/32", NULL});
    /* IPv6 first, an over-long entry, then the IPv4 /32 */
    char longip[300];
    memset(longip, '1', sizeof(longip) - 1);
    longip[sizeof(longip) - 1] = 0;
    w_peer(&map, KEY_B, (const char *const[]){"fd00:1234::3/128", longip, "100.64.0.3/32", NULL});
    /* only routed networks: no overlay address */
    w_peer(&map, KEY_C, (const char *const[]){"192.168.20.0/24", NULL});
    /* ourselves, a duplicate, broken keys */
    w_peer(&map, KEY_OWN, (const char *const[]){"100.64.0.1/32", NULL});
    w_peer(&map, KEY_A, (const char *const[]){"100.64.0.2/32", NULL});
    w_peer(&map, "short", (const char *const[]){"100.64.0.4/32", NULL});
    w_peer(&map, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", (const char *const[]){"100.64.0.5/32", NULL});
    w_peer(&map, NULL, (const char *const[]){"100.64.0.6/32", NULL});
    w_sync(&msg, &map);
    CHECK(decode(&msg, 8) == 0 && g_nm.has_map && g_nm.serial == 7);
    CHECK(g_nm.n_peers == 2);
    CHECK(!strcmp(g_peers[0].key, KEY_A) && g_peers[0].ip4 == ip("100.64.0.2"));
    CHECK(!strcmp(g_peers[1].key, KEY_B) && g_peers[1].ip4 == ip("100.64.0.3"));
    CHECK(g_nm.peers_total == 7 && g_nm.peers_unusable == 4); /* C, "short", the long key, no key */
    CHECK(g_nm.has_peer_config && !strcmp(g_nm.address, "100.64.0.1/16") && g_nm.mtu == 1280);

    /* more peers than fit */
    w_map_head(&map, 8, "100.64.0.1/16");
    char key[45], ipb[32];
    for (int i = 0; i < 6; i++) {
        memset(key, 'a' + i, 43);
        key[43] = '=';
        key[44] = 0;
        snprintf(ipb, sizeof(ipb), "100.64.3.%d/32", i + 1);
        w_peer(&map, key, (const char *const[]){ipb, NULL});
    }
    w_sync(&msg, &map);
    CHECK(decode(&msg, 8) == 0 && g_nm.n_peers == 4 && g_nm.peers_total == 6 && g_nm.peers_unusable == 0);
}

static void test_config(void)
{
    static buf_t map, msg, nc, sig, relay;
    char longv[400];
    memset(longv, 'x', sizeof(longv) - 1);
    longv[sizeof(longv) - 1] = 0;
    /* NetbirdConfig: stuns=1 (unknown here), signal=3 {uri=1 protocol=2}, relay=4 {urls=1 tokenPayload=2
     * tokenSignature=3}, flow=5 (unknown) */
    nc.n = sig.n = relay.n = 0;
    w_str(&nc, 1, longv); /* skipped */
    w_str(&sig, 1, "https://signal.example.com:443");
    w_int(&sig, 2, 3);
    w_msg(&nc, 3, &sig);
    w_str(&relay, 1, "rel://relay-plain.example.com:80");
    w_str(&relay, 1, longv);
    w_str(&relay, 1, "rels://relay-1.example.com:443");
    w_str(&relay, 1, "rels://relay-2.example.com:443");
    w_str(&relay, 2, "1760000000");
    w_str(&relay, 3, "c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmUtc2lnbg==");
    w_msg(&nc, 4, &relay);
    w_str(&nc, 5, longv);
    msg.n = 0;
    w_msg(&msg, 1, &nc);
    /* deprecated top-level fields of older servers are skipped */
    w_str(&msg, 2, longv);
    w_bytes(&msg, 3, longv, 300);
    w_map_head(&map, 9, "100.64.0.1/16");
    w_peer(&map, KEY_A, (const char *const[]){"100.64.0.2/32", NULL});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.2", .proto = TCP, .port = "22"});
    w_msg(&msg, 5, &map);
    CHECK(decode(&msg, 8) == 0);
    CHECK(g_nm.has_signal && !strcmp(g_nm.signal_uri, "https://signal.example.com:443") && g_nm.signal_protocol == 3);
    CHECK(g_nm.has_relay && !strcmp(g_nm.relay_url, "rels://relay-1.example.com:443"));
    CHECK(g_nm.relay_urls == 4 && g_nm.relay_urls_too_long == 1);
    CHECK(!strcmp(g_nm.relay_payload, "1760000000") && g_nm.relay_sig[0] && !g_nm.config_too_long);
    CHECK(g_nm.has_map && g_nm.n_peers == 1 && g_nm.n_rules == 1);

    /* over-long signal URI, token and address: ignored, the network map is still usable */
    nc.n = sig.n = relay.n = 0;
    w_str(&sig, 1, longv);
    w_msg(&nc, 3, &sig);
    w_str(&relay, 1, "rels://relay.example.com:443");
    w_str(&relay, 2, longv);
    w_str(&relay, 3, "sig");
    w_msg(&nc, 4, &relay);
    msg.n = 0;
    w_msg(&msg, 1, &nc);
    map.n = 0;
    w_int(&map, 1, 10);
    buf_t pc = {.n = 0};
    w_str(&pc, 1, longv);
    w_msg(&map, 2, &pc);
    w_peer(&map, KEY_A, (const char *const[]){"100.64.0.2/32", NULL});
    w_rule(&map, &(fw_t){.peer_ip = "100.64.0.2", .proto = TCP, .port = "22"});
    w_msg(&msg, 5, &map);
    CHECK(decode(&msg, 8) == 0);
    CHECK(!g_nm.has_signal && !g_nm.has_relay && g_nm.config_too_long);
    CHECK(g_nm.has_peer_config && g_nm.address[0] == 0);
    CHECK(g_nm.n_peers == 1 && g_nm.n_rules == 1 && g_nm.serial == 10);

    /* only a relay URL without rels://: kept (nbl_relay reports it) */
    nc.n = relay.n = 0;
    w_str(&relay, 1, "rel://plain.example.com:80");
    w_str(&relay, 3, "sig");
    w_msg(&nc, 4, &relay);
    msg.n = 0;
    w_msg(&msg, 1, &nc);
    CHECK(decode(&msg, 8) == 0 && g_nm.has_relay && !strcmp(g_nm.relay_url, "rel://plain.example.com:80"));
    CHECK(!g_nm.has_map);

    /* not protobuf at all */
    const uint8_t junk[] = {0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f, 1, 2};
    memcpy(msg.b, junk, sizeof(junk));
    msg.n = sizeof(junk);
    CHECK(decode(&msg, 8) == -1 && g_nm.error != NULL);
    /* the caller's tables survive a reset */
    CHECK(g_nm.peers == g_peers && g_nm.rules == g_rules && g_nm.max_rules == 8);
}

int main(void)
{
    test_parsers();
    test_rule_basic();
    test_rule_ports();
    test_rule_malformed();
    test_rule_prefixes();
    test_rule_truncation();
    test_peers();
    test_config();
    printf("test_rules: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
