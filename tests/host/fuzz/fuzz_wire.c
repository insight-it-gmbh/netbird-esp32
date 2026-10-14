// libFuzzer target for the decoders of untrusted control-plane input: the envelope decoder of
// nbl_wire.h (signal messages are relayed from any peer), the SyncResponse decoder nbl_netmap.c and
// a signal Body with the bounded string callbacks. Every result is checked against its invariants.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nbl_netmap.h"
#include "nbl_signal.pb.h"
#include "nbl_wire.h"
#include "pb_decode.h"

#define REQUIRE(c) do { if (!(c)) __builtin_trap(); } while (0)

static const char *OWN_KEY = "OwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnOwnA=";

/* a netmask in network byte order: ones, then zeros */
static int is_prefix_mask(uint32_t m)
{
    uint8_t b[4];
    memcpy(b, &m, 4);
    uint32_t h = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
    return (~h & (~h + 1)) == 0;
}

static int terminated(const char *s, size_t cap)
{
    return memchr(s, 0, cap) != NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536) {
        return 0;
    }

    /* 1. envelope: the first byte selects the field number (0..31, 0 is never valid) */
    {
        const uint8_t *in = data + 1;
        size_t n = size - 1;
        const uint8_t *d = NULL;
        size_t dl = 0;
        if (nbl_get_bytes(in, n, data[0] & 31, &d, &dl) == 0) {
            REQUIRE((data[0] & 31) != 0);
            REQUIRE(d >= in && d <= in + n && dl <= (size_t)(in + n - d));
            volatile uint8_t x = 0;
            for (size_t i = 0; i < dl; i++) {
                x ^= d[i];
            }
            (void)x;
        }
        uint64_t v;
        size_t used = nbl_get_varint(data, size, &v);
        REQUIRE(used <= 10 && used <= size);
    }

    /* 2. SyncResponse, with small tables (sizes from the first byte, 0 included) so that the
     *    truncation paths run */
    {
        nbl_nm_peer_t peers[3];
        nbl_acl_rule_t rules[7];
        const int max_peers = data[0] & 3, max_rules = (data[0] >> 2) & 7;
        nbl_netmap_t nm;
        memset(&nm, 0, sizeof(nm));
        nm.peers = max_peers ? peers : NULL;
        nm.max_peers = max_peers;
        nm.rules = max_rules ? rules : NULL;
        nm.max_rules = max_rules;
        nm.own_key = OWN_KEY;
        if (nbl_netmap_decode(data, size, &nm) == 0) {
            REQUIRE(nm.n_peers >= 0 && nm.n_peers <= max_peers && nm.n_rules >= 0 && nm.n_rules <= max_rules);
            REQUIRE(!nm.deny_lost || nm.n_rules == 0);
            REQUIRE(terminated(nm.signal_uri, sizeof(nm.signal_uri)) && terminated(nm.relay_url, sizeof(nm.relay_url)));
            REQUIRE(terminated(nm.relay_payload, sizeof(nm.relay_payload)));
            REQUIRE(terminated(nm.relay_sig, sizeof(nm.relay_sig)) && terminated(nm.address, sizeof(nm.address)));
            REQUIRE(!nm.has_relay || (nm.relay_url[0] && nm.relay_sig[0]));
            REQUIRE(!nm.has_signal || nm.signal_uri[0]);
            REQUIRE(nm.peers_unusable <= nm.peers_total && nm.n_peers <= nm.peers_total);
            REQUIRE(nm.fw_skipped + nm.fw_malformed <= nm.fw_total);
            for (int i = 0; i < nm.n_peers; i++) {
                REQUIRE(terminated(peers[i].key, sizeof(peers[i].key)) && strlen(peers[i].key) == 44);
                REQUIRE(strcmp(peers[i].key, OWN_KEY) != 0);
                for (int j = 0; j < i; j++) {
                    REQUIRE(strcmp(peers[i].key, peers[j].key) != 0);
                }
            }
            for (int i = 0; i < nm.n_rules; i++) {
                const nbl_acl_rule_t *r = &rules[i];
                REQUIRE(r->action == NBL_ACL_ACCEPT || r->action == NBL_ACL_DROP);
                REQUIRE(is_prefix_mask(r->mask));
                REQUIRE(r->p0 <= r->p1 && (r->p0 == 0) == (r->p1 == 0));
                REQUIRE(r->p0 == 0 || r->proto == 0 || r->proto == 6 || r->proto == 17);
            }
        }
    }

    /* 3. signal Body with the string callbacks */
    {
        char ver[32], relay[NBL_NM_RELAY_URL_CAP];
        nbl_pb_str_t va = {ver, sizeof(ver), false, false}, ra = {relay, sizeof(relay), false, false};
        ver[0] = relay[0] = 0;
        signalexchange_Body b = signalexchange_Body_init_zero;
        b.netBirdVersion.funcs.decode = nbl_pb_decode_str;
        b.netBirdVersion.arg = &va;
        b.relayServerAddress.funcs.decode = nbl_pb_decode_str;
        b.relayServerAddress.arg = &ra;
        pb_istream_t is = pb_istream_from_buffer(data, size);
        if (pb_decode(&is, signalexchange_Body_fields, &b)) {
            REQUIRE(terminated(ver, sizeof(ver)) && terminated(relay, sizeof(relay)));
            REQUIRE(!ra.bad || !relay[0]);
        }
    }
    return 0;
}
