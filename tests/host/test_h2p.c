// Host tests for the HTTP/2 core (nbl_h2p): HPACK (RFC 7541 test vectors), framing, flow control.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nbl_h2p.h"
#include "nbl_huff.inc" /* for the test-side Huffman encoder */

static int fails, checks;
static char last_err[96]; /* last reason passed to on_error, printed with a failed check */
#define CHECK(cond)                                                    \
    do {                                                               \
        checks++;                                                      \
        if (!(cond)) {                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            if (last_err[0]) {                                         \
                printf("     last protocol error: %s\n", last_err);    \
            }                                                          \
            fails++;                                                   \
        }                                                              \
    } while (0)

static nbl_h2p_stream_t SLOTS[8];
static nbl_h2p_t *H;

struct evlog {
    char headers[8][8][128];
    int nh[8];
    uint32_t hids[8];
    bool hdr_done[8];
    bool hdr_end[8];
    uint8_t data[8192];
    size_t data_len;
    uint32_t data_id;
    int data_msgs;
    bool data_end;
    uint32_t closed[8];
    uint32_t closed_err[8];
    int nclosed;
    int goaway;
    uint32_t goaway_last, goaway_err;
    int errors;
} EV;

static int ev_streams; /* number of stream slots used in EV */

static bool ev_has(uint32_t id, const char *needle)
{
    for (int j = 0; j < ev_streams; j++) {
        if (EV.hids[j] != id) {
            continue;
        }
        for (int k = 0; k < EV.nh[j]; k++) {
            if (strstr(EV.headers[j][k], needle)) {
                return true;
            }
        }
    }
    return false;
}

static int ev_count(uint32_t id) /* number of header fields reported for a stream */
{
    for (int j = 0; j < ev_streams; j++) {
        if (EV.hids[j] == id) {
            return EV.nh[j];
        }
    }
    return 0;
}

static void ev_reset(void) { memset(&EV, 0, sizeof(EV)); ev_streams = 0; last_err[0] = 0; }

static void ev_header(void *ctx, uint32_t id, const char *n, const char *v)
{
    struct evlog *e = ctx;
    int slot = -1;
    for (int j = 0; j < ev_streams; j++) {
        if (e->hids[j] == id) {
            slot = j;
            break;
        }
    }
    if (slot < 0 && ev_streams < 8) {
        slot = ev_streams++;
        e->hids[slot] = id;
        e->nh[slot] = 0;
    }
    if (slot >= 0 && e->nh[slot] < 8) {
        snprintf(e->headers[slot][e->nh[slot]++], 128, "%s=%s", n, v);
    }
}

static void ev_header_done(void *ctx, uint32_t id, bool end)
{
    struct evlog *e = ctx;
    for (int j = 0; j < 8; j++) {
        if (e->hids[j] == id) {
            e->hdr_done[j] = true;
            e->hdr_end[j] = end;
        }
    }
}

static void ev_data(void *ctx, uint32_t id, const uint8_t *d, size_t len, bool end)
{
    struct evlog *e = ctx;
    e->data_id = id;
    if (e->data_len + len < sizeof(e->data)) {
        memcpy(e->data + e->data_len, d, len);
        e->data_len += len;
    }
    e->data_msgs++;
    if (end) {
        e->data_end = true;
    }
}

static void ev_closed(void *ctx, uint32_t id, uint32_t err)
{
    struct evlog *e = ctx;
    if (e->nclosed < 8) {
        e->closed_err[e->nclosed] = err;
        e->closed[e->nclosed++] = id;
    }
}

static void ev_goaway(void *ctx, uint32_t last, uint32_t err)
{
    struct evlog *e = ctx;
    e->goaway++;
    e->goaway_last = last;
    e->goaway_err = err;
}

static void ev_err(void *ctx, const char *why)
{
    ((struct evlog *)ctx)->errors++;
    snprintf(last_err, sizeof(last_err), "%s", why);
}

static const nbl_h2p_cb_t CB = {.on_header = ev_header, .on_headers_done = ev_header_done, .on_data = ev_data,
                                .on_stream_closed = ev_closed, .on_goaway = ev_goaway, .on_error = ev_err};

/* ---------------- client output: captured and split into frames ---------------- */

static uint8_t OUT[1 << 17]; /* everything the client sent since out_reset() */
static size_t OUTN;

static void out_reset(void) { OUTN = 0; }

static void drain(void)
{
    while (nbl_h2p_want_write(H)) {
        size_t n = nbl_h2p_output(H, OUT + OUTN, sizeof(OUT) - OUTN);
        OUTN += n;
        if (!n) {
            break;
        }
    }
}

static void flush_out(void) /* send and forget everything queued so far */
{
    drain();
    out_reset();
}

struct fr {
    uint8_t type, flags;
    uint32_t id;
    const uint8_t *pl;
    size_t len;
};
static struct fr FR[2048];
static int NFR;

/* drains the output and splits it into frames; -1 if it does not end on a frame boundary */
static int out_frames(void)
{
    drain();
    size_t o = 0;
    NFR = 0;
    while (o < OUTN) {
        if (OUTN - o < 9 || NFR == (int)(sizeof(FR) / sizeof(FR[0]))) {
            return -1;
        }
        size_t len = (size_t)OUT[o] << 16 | (size_t)OUT[o + 1] << 8 | OUT[o + 2];
        if (OUTN - o - 9 < len) {
            return -1;
        }
        FR[NFR++] = (struct fr){OUT[o + 3], OUT[o + 4],
                                ((uint32_t)OUT[o + 5] << 24 | (uint32_t)OUT[o + 6] << 16 | (uint32_t)OUT[o + 7] << 8 |
                                 OUT[o + 8]),
                                OUT + o + 9, len};
        o += 9 + len;
    }
    return NFR;
}

static int n_frames(uint8_t type, uint32_t id)
{
    int n = 0;
    for (int i = 0; i < NFR; i++) {
        n += FR[i].type == type && FR[i].id == id;
    }
    return n;
}

static uint32_t wu_sum(uint32_t id) /* WINDOW_UPDATE credit given for a stream (0 = connection) */
{
    uint32_t sum = 0;
    for (int i = 0; i < NFR; i++) {
        if (FR[i].type == 8 && FR[i].id == id && FR[i].len == 4) {
            sum += (uint32_t)FR[i].pl[0] << 24 | (uint32_t)FR[i].pl[1] << 16 | (uint32_t)FR[i].pl[2] << 8 | FR[i].pl[3];
        }
    }
    return sum;
}

/* ---------------- server input ---------------- */

/* nbl_h2p_input() as the glue uses it: when the core stops early, send and pass the rest */
static int feed(const uint8_t *d, size_t n)
{
    while (n) {
        int used = nbl_h2p_input(H, d, n);
        if (used < 0) {
            return -1;
        }
        d += used;
        n -= (size_t)used;
        if (n) {
            if (!nbl_h2p_want_write(H)) {
                return -2; /* would never make progress */
            }
            drain();
        }
    }
    return 0;
}

/* build a complete frame */
static size_t frame(uint8_t *o, uint8_t type, uint8_t flags, uint32_t id, const void *pl, size_t len)
{
    o[0] = (uint8_t)(len >> 16);
    o[1] = (uint8_t)(len >> 8);
    o[2] = (uint8_t)len;
    o[3] = type;
    o[4] = flags;
    o[5] = (uint8_t)(id >> 24);
    o[6] = (uint8_t)(id >> 16);
    o[7] = (uint8_t)(id >> 8);
    o[8] = (uint8_t)id;
    if (len) {
        memcpy(o + 9, pl, len);
    }
    return 9 + len;
}

static int feed_frame(uint8_t type, uint8_t flags, uint32_t id, const void *pl, size_t len)
{
    static uint8_t fr[9 + 16384];
    return feed(fr, frame(fr, type, flags, id, pl, len));
}

static void setup_fresh(void)
{
    static nbl_h2p_t h;
    if (H) {
        nbl_h2p_free(H); /* buffered data of the previous test */
    }
    H = &h;
    ev_reset();
    nbl_h2p_init(H, &CB, &EV, SLOTS, 8);
    nbl_h2p_start(H);
    flush_out(); /* client preface, SETTINGS, connection WINDOW_UPDATE */
}

static void setup(void)
{
    setup_fresh();
    CHECK(feed_frame(4, 0, 0, NULL, 0) == 0); /* server preface: empty SETTINGS */
    flush_out(); /* SETTINGS ACK */
}

static uint32_t open_stream(bool has_body)
{
    uint32_t id = 0;
    nbl_h2p_hdr_t h1[] = {{":method", "POST"}};
    CHECK(nbl_h2p_open_stream(H, h1, 1, has_body, &id) == 0);
    flush_out(); /* our HEADERS frame */
    return id;
}

/* HPACK integer with an n-bit prefix */
static size_t hp_int(uint8_t *o, uint64_t v, unsigned prefix, uint8_t first)
{
    uint64_t max = (1u << prefix) - 1;
    size_t n = 0;
    if (v < max) {
        o[n++] = first | (uint8_t)v;
        return n;
    }
    o[n++] = first | (uint8_t)max;
    for (v -= max; v >= 0x80; v >>= 7) {
        o[n++] = (uint8_t)(v | 0x80);
    }
    o[n++] = (uint8_t)v;
    return n;
}

/* literal header field without indexing, with a literal name (any lengths) */
static size_t hdr_lit(uint8_t *o, const char *name, const char *val)
{
    size_t n = 0, nl = strlen(name), vl = strlen(val);
    o[n++] = 0x00;
    n += hp_int(o + n, nl, 7, 0);
    memcpy(o + n, name, nl);
    n += nl;
    n += hp_int(o + n, vl, 7, 0);
    memcpy(o + n, val, vl);
    return n + vl;
}

/* literal header field without indexing, with a literal name (short strings) */
static size_t hdr_lit_name(uint8_t *o, const char *name, const char *val)
{
    return hdr_lit(o, name, val);
}

/* Huffman-encoded string literal (RFC 7541 5.2) */
static size_t hp_huff(uint8_t *o, const char *s)
{
    uint8_t tmp[4096];
    size_t n = 0;
    uint64_t acc = 0;
    int bits = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        acc = acc << nbl_huff_table[*p].bits | nbl_huff_table[*p].code;
        bits += nbl_huff_table[*p].bits;
        while (bits >= 8) {
            tmp[n++] = (uint8_t)(acc >> (bits - 8));
            bits -= 8;
        }
        acc &= (1ULL << bits) - 1;
    }
    if (bits) { /* pad with the EOS prefix (all ones) */
        tmp[n++] = (uint8_t)(acc << (8 - bits) | ((1u << (8 - bits)) - 1));
    }
    size_t h = hp_int(o, n, 7, 0x80);
    memcpy(o + h, tmp, n);
    return h + n;
}

static char *repeat(char c, size_t n)
{
    char *s = malloc(n + 1);
    memset(s, c, n);
    s[n] = 0;
    return s;
}

/* ---------------- tests ---------------- */

static void test_hpack_rfc(void)
{
    setup();
    /* RFC 7541 C.3.1 (request, no Huffman coding):
       :method GET, :scheme http, :path /, :authority www.example.com */
    static const uint8_t c31[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
                                  0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d};
    CHECK(feed_frame(1, 0x4, 1, c31, sizeof(c31)) == 0);
    CHECK(EV.hdr_done[0]);
    CHECK(ev_has(1, ":method=GET") && ev_has(1, ":scheme=http") && ev_has(1, ":path=/") &&
          ev_has(1, ":authority=www.example.com"));

    /* RFC 7541 C.6.1 (response, Huffman coded): :status 302, cache-control: private,
       date: Mon, 21 Oct 2013 20:13:21 GMT, location: https://www.example.com */
    ev_reset();
    static const uint8_t c61[] = {0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b,
                                  0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
                                  0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
                                  0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b,
                                  0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3};
    CHECK(feed_frame(1, 0x4, 1, c61, sizeof(c61)) == 0);
    CHECK(EV.hdr_done[0]);
    CHECK(ev_has(1, ":status=302"));
    CHECK(ev_has(1, "cache-control=private"));
    CHECK(ev_has(1, "location=https://www.example.com"));
    CHECK(ev_has(1, "date=Mon, 21 Oct 2013 20:13:21 GMT"));

    /* header with a literal name (as gRPC trailers use) + END_STREAM */
    ev_reset();
    uint8_t blk[64];
    size_t o = 0;
    blk[o++] = 0x88; /* :status 200 */
    o += hdr_lit_name(blk + o, "grpc-status", "0");
    CHECK(feed_frame(1, 0x4 | 0x1, 1, blk, o) == 0);
    CHECK(EV.hdr_end[0]);
    CHECK(ev_has(1, "grpc-status=0"));

    /* the test-side Huffman encoder agrees with the decoder */
    ev_reset();
    o = 0;
    blk[o++] = 0x0f; /* literal without indexing, name index 31 (content-type) = 15 + 16 */
    blk[o++] = 16;
    o += hp_huff(blk + o, "application/grpc");
    CHECK(feed_frame(1, 0x4, 1, blk, o) == 0);
    CHECK(ev_has(1, "content-type=application/grpc"));
}

static void test_frames(void)
{
    setup();
    /* SETTINGS from the server (with a new initial window size) must queue a SETTINGS ACK */
    uint8_t set[6] = {0x00, 0x04, 0x00, 0x10, 0x00, 0x00}; /* INITIAL_WINDOW_SIZE = 1 MiB */
    CHECK(feed_frame(4, 0, 0, set, 6) == 0);
    CHECK(out_frames() == 1 && FR[0].type == 4 && FR[0].flags == 0x1 && FR[0].len == 0); /* SETTINGS ACK */

    /* PING -> PING ACK with the same payload */
    out_reset();
    CHECK(feed_frame(6, 0, 0, "12345678", 8) == 0);
    CHECK(out_frames() == 1 && FR[0].type == 6 && (FR[0].flags & 1) && !memcmp(FR[0].pl, "12345678", 8));

    /* DATA on an opened stream */
    uint32_t id = open_stream(true);
    CHECK(nbl_h2p_stream_open(H, id));
    CHECK(feed_frame(0, 0, id, "hello", 5) == 0);
    CHECK(EV.data_len == 5 && !memcmp(EV.data, "hello", 5) && !EV.data_end);
    /* flow control: WINDOW_UPDATE for the connection and for the stream are queued */
    CHECK(out_frames() == 2 && wu_sum(0) == 5 && wu_sum(id) == 5);

    /* RST_STREAM closes the stream */
    ev_reset();
    CHECK(feed_frame(3, 0, id, "\x00\x00\x00\x08", 4) == 0);
    CHECK(EV.nclosed == 1 && EV.closed[0] == id && EV.closed_err[0] == 8);
    CHECK(!nbl_h2p_stream_open(H, id));

    /* GOAWAY */
    CHECK(feed_frame(7, 0, 0, "\x00\x00\x00\x01\x00\x00\x00\x00", 8) == 0);
    CHECK(EV.goaway == 1);
    CHECK(H->dead);

    /* SETTINGS payload length not a multiple of 6 -> connection error */
    setup();
    CHECK(feed_frame(4, 0, 0, "abc", 3) < 0);
}

static void test_send_flow(void)
{
    setup();
    uint32_t id = open_stream(true);
    /* the server sets the initial window to 0 -> sending must buffer */
    uint8_t set[6] = {0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
    CHECK(feed_frame(4, 0, 0, set, 6) == 0);
    flush_out();
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"abcdef", 6, true) == 1); /* buffered */
    CHECK(!nbl_h2p_want_write(H));
    /* WINDOW_UPDATE by 10 -> the buffered data goes out */
    uint8_t wu[4] = {0, 0, 0, 10};
    CHECK(feed_frame(8, 0, 0, wu, 4) == 0); /* connection */
    CHECK(!nbl_h2p_want_write(H));          /* the stream window is still 0 */
    CHECK(feed_frame(8, 0, id, wu, 4) == 0); /* stream */
    CHECK(out_frames() == 1);                /* one DATA frame, 6 bytes, END_STREAM */
    CHECK(FR[0].type == 0 && (FR[0].flags & 0x1) && FR[0].len == 6 && !memcmp(FR[0].pl, "abcdef", 6));

    /* appending while earlier data is still buffered keeps the order */
    id = open_stream(true);
    out_reset();
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"abc", 3, false) == 1);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"def", 3, true) == 1);
    uint8_t s4[6] = {0x00, 0x04, 0x00, 0x00, 0x00, 0x04}; /* INITIAL_WINDOW_SIZE = 4 */
    CHECK(feed_frame(4, 0, 0, s4, 6) == 0);
    CHECK(out_frames() == 2 && n_frames(0, id) == 1);
    for (int i = 0; i < NFR; i++) {
        if (FR[i].type == 0) {
            CHECK(FR[i].len == 4 && !(FR[i].flags & 0x1) && !memcmp(FR[i].pl, "abcd", 4));
        }
    }
    out_reset();
    uint8_t wu2[4] = {0, 0, 0, 2};
    CHECK(feed_frame(8, 0, id, wu2, 4) == 0); /* the connection window is large */
    CHECK(out_frames() == 1 && FR[0].len == 2 && (FR[0].flags & 0x1) && !memcmp(FR[0].pl, "ef", 2));
}

static void test_stream_ids(void)
{
    setup();
    /* Regression: after more than streams_cap streams in total, IDs above 15 must still be
       found (an earlier version lost every stream from the 9th one on) */
    uint32_t ids[12];
    nbl_h2p_hdr_t h1[] = {{":method", "POST"}};
    for (int i = 0; i < 8; i++) {
        CHECK(nbl_h2p_open_stream(H, h1, 1, true, &ids[i]) == 0);
    }
    /* all 8 slots are in use now; a 9th stream must fail */
    CHECK(nbl_h2p_open_stream(H, h1, 1, true, &ids[8]) != 0);
    /* close one and open again -> high stream ID */
    nbl_h2p_reset(H, ids[0]);
    CHECK(nbl_h2p_open_stream(H, h1, 1, true, &ids[0]) == 0);
    CHECK(ids[0] >= 17);
    CHECK(nbl_h2p_stream_open(H, ids[0])); /* <<< the actual regression check */
    /* DATA on that stream must be delivered */
    CHECK(feed_frame(0, 0x1, ids[0], "hi", 2) == 0);
    CHECK(EV.data_len == 2 && !memcmp(EV.data, "hi", 2));
}

static void test_continuation(void)
{
    setup();
    uint8_t blk[1] = {0x88}; /* :status 200 */
    /* HEADERS without END_HEADERS, then an empty CONTINUATION with END_HEADERS */
    CHECK(feed_frame(1, 0x0, 1, blk, 1) == 0);
    CHECK(!EV.hdr_done[0]);
    CHECK(feed_frame(9, 0x4, 1, NULL, 0) == 0);
    CHECK(EV.hdr_done[0]);
}

/* F1: many small DATA frames plus PINGs in one input: nothing lost, WINDOW_UPDATEs coalesced */
static void test_burst(void)
{
    setup();
    uint32_t id = open_stream(true);
    static uint8_t in[300 * 17];
    size_t o = 0;
    int pings = 0;
    for (int i = 0; i < 250; i++) {
        uint8_t c = (uint8_t)('a' + i % 26);
        o += frame(in + o, 0, 0, id, &c, 1);
        if (i % 50 == 49) {
            char p[24];
            snprintf(p, sizeof(p), "ping%04d", pings++);
            o += frame(in + o, 6, 0, 0, p, 8);
        }
    }
    CHECK(nbl_h2p_input(H, in, o) == (int)o); /* all consumed in one call */
    CHECK(EV.data_msgs == 250 && EV.data_len == 250);
    bool same = true;
    for (int i = 0; i < 250; i++) {
        same = same && EV.data[i] == 'a' + i % 26;
    }
    CHECK(same);
    CHECK(out_frames() == pings + 2);
    CHECK(n_frames(6, 0) == pings && n_frames(8, 0) == 1 && n_frames(8, id) == 1);
    CHECK(wu_sum(0) == 250 && wu_sum(id) == 250);
    int k = 0;
    for (int i = 0; i < NFR; i++) {
        if (FR[i].type == 6) {
            char p[24];
            snprintf(p, sizeof(p), "ping%04d", k++);
            CHECK((FR[i].flags & 1) && FR[i].len == 8 && !memcmp(FR[i].pl, p, 8));
        }
    }

    /* 300 PINGs (5100 bytes of answers, more than the send queue): the core stops early
       instead of dropping answers; the caller sends and passes the rest */
    out_reset();
    o = 0;
    for (int i = 0; i < 300; i++) {
        char p[24];
        snprintf(p, sizeof(p), "%08d", i);
        o += frame(in + o, 6, 0, 0, p, 8);
    }
    int used = nbl_h2p_input(H, in, o);
    CHECK(used > 0 && used < (int)o);
    CHECK(used > 0 && feed(in + used, o - (size_t)used) == 0);
    CHECK(out_frames() == 300 && n_frames(6, 0) == 300);
    bool order = true;
    for (int i = 0; i < NFR; i++) {
        char p[24];
        snprintf(p, sizeof(p), "%08d", i);
        order = order && FR[i].len == 8 && !memcmp(FR[i].pl, p, 8);
    }
    CHECK(order);
    CHECK(EV.errors == 0 && !H->dead);
}

/* F1: sending is atomic per frame and messages larger than the send queue go out in chunks */
static void test_send_queue(void)
{
    setup();
    uint32_t id = open_stream(true);
    /* fill the queue with PINGs: frames go in whole or not at all */
    int pings = 0;
    while (nbl_h2p_ping(H) == 0) {
        pings++;
    }
    size_t full = H->out_len;
    CHECK(pings > 0 && full <= NBL_H2P_OUT_CAP && NBL_H2P_OUT_CAP - full < 17);
    uint32_t id2;
    nbl_h2p_hdr_t h1[] = {{":method", "POST"}};
    CHECK(nbl_h2p_open_stream(H, h1, 1, true, &id2) < 0); /* no room: nothing queued */
    CHECK(H->out_len == full);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"xyz", 3, false) == 1); /* buffered */
    CHECK(H->out_len == full);
    CHECK(out_frames() == pings + 1 && FR[pings].type == 0 && FR[pings].len == 3);
    CHECK(nbl_h2p_open_stream(H, h1, 1, true, &id2) == 0); /* room again */
    flush_out();

    /* 10000 bytes (window 65535): all of it goes out in DATA frames, END_STREAM on the last */
    static uint8_t big[70000];
    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 7 + i / 251);
    }
    CHECK(nbl_h2p_send_data(H, id, big, 10000, true) == 1);
    CHECK(out_frames() > 2);
    size_t got = 0;
    bool ok = true;
    for (int i = 0; i < NFR; i++) {
        ok = ok && FR[i].type == 0 && FR[i].id == id && FR[i].len <= NBL_H2P_OUT_CAP;
        ok = ok && !memcmp(FR[i].pl, big + got, FR[i].len);
        ok = ok && ((FR[i].flags & 0x1) != 0) == (i == NFR - 1);
        got += FR[i].len;
    }
    CHECK(ok && got == 10000);
    CHECK(nbl_h2p_send_data(H, id, big, 1, false) < 0); /* stream ended */

    /* 70000 bytes on a fresh connection: limited by the 65535-byte windows, the rest follows
       the WINDOW_UPDATEs */
    setup();
    id = open_stream(true);
    CHECK(nbl_h2p_send_data(H, id, big, sizeof(big), true) == 1);
    CHECK(out_frames() > 0);
    got = 0;
    for (int i = 0; i < NFR; i++) {
        got += FR[i].type == 0 ? FR[i].len : 0;
    }
    CHECK(got == 65535 && !(FR[NFR - 1].flags & 0x1));
    CHECK(nbl_h2p_send_data(H, id, big, 1, false) < 0); /* END_STREAM requested already */
    out_reset();
    uint8_t wu[4] = {0, 0, 0x27, 0x10}; /* 10000 */
    CHECK(feed_frame(8, 0, 0, wu, 4) == 0 && feed_frame(8, 0, id, wu, 4) == 0);
    CHECK(out_frames() > 0);
    size_t rest = 0;
    ok = true;
    for (int i = 0; i < NFR; i++) {
        ok = ok && FR[i].type == 0 && !memcmp(FR[i].pl, big + 65535 + rest, FR[i].len);
        rest += FR[i].len;
    }
    CHECK(ok && rest == sizeof(big) - 65535 && (FR[NFR - 1].flags & 0x1));
    CHECK(!nbl_h2p_want_write(H));
}

/* F2: oversized header fields are dropped, header blocks larger than the buffer work */
static void test_big_headers(void)
{
    setup();
    uint32_t id = open_stream(true);
    static uint8_t blk[16384];
    char *v2k = repeat('v', 2048), *n200 = repeat('n', 200), *a400 = repeat('a', 400);
    size_t o = 0;
    blk[o++] = 0x88;                                    /* :status 200 */
    o += hdr_lit(blk + o, "x-big", v2k);                /* 2 KB value: dropped */
    o += hdr_lit(blk + o, n200, "x");                   /* 200-byte name: dropped */
    blk[o++] = 0x00;                                    /* Huffman value of 400 'a' (250 bytes) */
    o += hp_int(blk + o, 7, 7, 0);
    memcpy(blk + o, "x-huffa", 7);
    o += 7;
    o += hp_huff(blk + o, a400);                        /* decodes to more than 383: dropped */
    o += hdr_lit(blk + o, "content-type", "application/grpc");
    CHECK(feed_frame(1, 0x4, id, blk, o) == 0);
    CHECK(ev_has(id, ":status=200") && ev_has(id, "content-type=application/grpc"));
    CHECK(ev_count(id) == 2 && EV.hdr_done[0] && !EV.hdr_end[0]);

    /* trailers: > 4 KB block in HEADERS + CONTINUATION frames, cut at odd places (inside
       length prefixes and strings) */
    ev_reset();
    o = 0;
    o += hdr_lit(blk + o, "x-a", v2k);
    o += hdr_lit(blk + o, n200, v2k);
    o += hdr_lit(blk + o, "grpc-status", "0");
    o += hdr_lit(blk + o, "x-b", v2k);
    o += hdr_lit(blk + o, "grpc-message", "fine");
    CHECK(o > 6000);
    size_t off = 0;
    bool first = true;
    while (off < o) {
        size_t n = o - off < 997 ? o - off : 997;
        uint8_t fl = off + n == o ? 0x4 : 0;
        CHECK(feed_frame(first ? 1 : 9, first ? (uint8_t)(fl | 0x1) : fl, id, blk + off, n) == 0);
        first = false;
        off += n;
    }
    CHECK(ev_has(id, "grpc-status=0") && ev_has(id, "grpc-message=fine") && ev_count(id) == 2);
    CHECK(EV.hdr_done[0] && EV.hdr_end[0]);
    CHECK(EV.nclosed == 1 && EV.closed[0] == id && !nbl_h2p_stream_open(H, id));
    CHECK(EV.errors == 0);

    /* the same block delivered byte by byte (1-byte CONTINUATION frames) */
    setup();
    id = open_stream(true);
    CHECK(feed_frame(1, 0x1, id, blk, 1) == 0);
    for (off = 1; off < o; off++) {
        if (feed_frame(9, off + 1 == o ? 0x4 : 0, id, blk + off, 1) != 0) {
            break;
        }
    }
    CHECK(off == o && ev_has(id, "grpc-status=0") && ev_has(id, "grpc-message=fine") && ev_count(id) == 2);

    /* a block that ends inside a skipped string is a COMPRESSION_ERROR */
    setup();
    id = open_stream(true);
    o = hdr_lit(blk, "x-a", v2k);
    CHECK(feed_frame(1, 0x4, id, blk, o - 1) < 0);
    free(v2k);
    free(n200);
    free(a400);
}

/* F12: huge length prefixes neither crash nor wrap around */
static void test_hpack_lengths(void)
{
    setup();
    uint32_t id = open_stream(true);
    uint8_t blk[64];
    size_t o = 0;
    blk[o++] = 0x00; /* literal name with a length of 2^62 */
    o += hp_int(blk + o, 1ULL << 62, 7, 0);
    memcpy(blk + o, "abc", 3);
    o += 3;
    CHECK(feed_frame(1, 0x0, id, blk, o) == 0); /* dropped, the rest still expected */
    CHECK(feed_frame(9, 0x4, id, "x", 1) < 0);  /* block ends inside the string */

    setup();
    id = open_stream(true);
    o = 0;
    blk[o++] = 0x0f; /* content-type, value length 2^60 */
    blk[o++] = 16;
    o += hp_int(blk + o, 1ULL << 60, 7, 0);
    CHECK(feed_frame(1, 0x4, id, blk, o) < 0);

    setup();
    id = open_stream(true);
    static const uint8_t toolong[] = {0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01};
    CHECK(feed_frame(1, 0x4, id, toolong, sizeof(toolong)) < 0); /* integer > 64 bits */

    /* dynamic table size update: 0 at the start of a block is fine, after a field it is not */
    setup();
    id = open_stream(true);
    CHECK(feed_frame(1, 0x4, id, "\x20\x88", 2) == 0 && ev_has(id, ":status=200"));
    CHECK(feed_frame(1, 0x4, id, "\x88\x20", 2) < 0);
    setup();
    id = open_stream(true);
    CHECK(feed_frame(1, 0x4, id, "\x3f\xe1\x1f\x88", 4) < 0); /* size 4096: we announced 0 */
}

/* F3: SETTINGS 0x3 is MAX_CONCURRENT_STREAMS, 0x5 is MAX_FRAME_SIZE */
static void test_settings(void)
{
    setup();
    uint8_t s3[6] = {0, 3, 0, 0x10, 0, 0}; /* MAX_CONCURRENT_STREAMS = 1048576 */
    CHECK(feed_frame(4, 0, 0, s3, 6) == 0 && H->peer_max_frame == 16384);
    uint8_t s5[6] = {0, 5, 0, 0, 0x80, 0}; /* MAX_FRAME_SIZE = 32768 */
    CHECK(feed_frame(4, 0, 0, s5, 6) == 0 && H->peer_max_frame == 32768);
    uint8_t s5max[6] = {0, 5, 0, 0xff, 0xff, 0xff};
    CHECK(feed_frame(4, 0, 0, s5max, 6) == 0 && H->peer_max_frame == 16777215);
    uint8_t s5low[6] = {0, 5, 0, 0, 0x10, 0}; /* 4096: PROTOCOL_ERROR */
    CHECK(feed_frame(4, 0, 0, s5low, 6) < 0);
    setup();
    uint8_t s5high[6] = {0, 5, 0x01, 0, 0, 0}; /* 2^24 */
    CHECK(feed_frame(4, 0, 0, s5high, 6) < 0);
    setup();
    uint8_t s4[6] = {0, 4, 0x80, 0, 0, 0}; /* INITIAL_WINDOW_SIZE 2^31 */
    CHECK(feed_frame(4, 0, 0, s4, 6) < 0);

    /* our SETTINGS announce MAX_HEADER_LIST_SIZE */
    nbl_h2p_free(H);
    nbl_h2p_init(H, &CB, &EV, SLOTS, 8);
    nbl_h2p_start(H);
    out_reset();
    uint8_t pre[24];
    CHECK(nbl_h2p_output(H, pre, sizeof(pre)) == 24 && !memcmp(pre, "PRI * HTTP/2.0", 14));
    CHECK(out_frames() == 2 && FR[0].type == 4 && FR[0].len == 24);
    bool hl = false;
    for (size_t i = 0; i + 6 <= FR[0].len; i += 6) {
        const uint8_t *e = FR[0].pl + i;
        hl = hl || (e[0] == 0 && e[1] == 6 &&
                    ((uint32_t)e[2] << 24 | (uint32_t)e[3] << 16 | (uint32_t)e[4] << 8 | e[5]) == NBL_H2P_MAX_HDRLIST);
    }
    CHECK(hl);
}

/* F4: INITIAL_WINDOW_SIZE: overflow is a FLOW_CONTROL_ERROR, growth releases buffered data */
static void test_window_settings(void)
{
    setup();
    uint32_t id = open_stream(true);
    uint8_t wu[4] = {0x7f, 0xff, 0x00, 0x00};
    CHECK(feed_frame(8, 0, id, wu, 4) == 0);
    uint8_t s4[6] = {0, 4, 0x7f, 0xff, 0xff, 0xff};
    CHECK(feed_frame(4, 0, 0, s4, 6) < 0);

    setup();
    id = open_stream(true);
    uint8_t z[6] = {0, 4, 0, 0, 0, 0};
    CHECK(feed_frame(4, 0, 0, z, 6) == 0);
    flush_out();
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"abcdef", 6, true) == 1 && !nbl_h2p_want_write(H));
    uint8_t s100[6] = {0, 4, 0, 0, 0, 100};
    CHECK(feed_frame(4, 0, 0, s100, 6) == 0);
    CHECK(out_frames() == 2 && n_frames(4, 0) == 1 && n_frames(0, id) == 1);
    for (int i = 0; i < NFR; i++) {
        if (FR[i].type == 0) {
            CHECK(FR[i].len == 6 && (FR[i].flags & 1) && !memcmp(FR[i].pl, "abcdef", 6));
        }
    }
    /* shrinking makes the window negative; that is allowed */
    id = open_stream(true); /* window 100 */
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"0123456789", 10, false) == 0);
    CHECK(nbl_h2p_can_send(H, id));
    CHECK(feed_frame(4, 0, 0, z, 6) == 0 && !nbl_h2p_can_send(H, id)); /* window -10 */
    uint8_t s50[6] = {0, 4, 0, 0, 0, 50};
    CHECK(feed_frame(4, 0, 0, s50, 6) == 0 && nbl_h2p_can_send(H, id)); /* window 40 */
}

/* F5: padding and DATA on closed streams are credited back */
static void test_recv_credit(void)
{
    setup();
    uint32_t id = open_stream(true);
    uint8_t pd[11] = {5, 'a', 'b', 'c', 'd', 'e', 0, 0, 0, 0, 0};
    CHECK(feed_frame(0, 0x8, id, pd, sizeof(pd)) == 0);
    CHECK(EV.data_len == 5 && !memcmp(EV.data, "abcde", 5));
    CHECK(out_frames() == 2 && wu_sum(0) == 11 && wu_sum(id) == 11);

    /* DATA after our RST_STREAM: connection credit only */
    CHECK(nbl_h2p_reset(H, id) == 0);
    flush_out();
    CHECK(feed_frame(0, 0, id, "0123456789", 10) == 0);
    CHECK(out_frames() == 1 && wu_sum(0) == 10);
    /* never opened stream, and a padded frame consisting of padding only */
    out_reset();
    uint8_t padonly[4] = {3, 0, 0, 0};
    CHECK(feed_frame(0, 0x8, 99, padonly, 4) == 0);
    CHECK(out_frames() == 1 && wu_sum(0) == 4);
    /* invalid padding */
    uint8_t bad[3] = {3, 0, 0};
    CHECK(feed_frame(0, 0x8, 99, bad, 3) < 0);
}

/* F6: the server ending a stream closes it, even without RST_STREAM */
static void test_remote_end(void)
{
    setup();
    uint32_t id = open_stream(true); /* our side stays open, like the signal ConnectStream */
    CHECK(feed_frame(1, 0x4, id, "\x88", 1) == 0);
    CHECK(feed_frame(0, 0, id, "\x00\x00\x00\x00\x01Z", 6) == 0);
    uint8_t blk[64];
    size_t o = hdr_lit(blk, "grpc-status", "0");
    flush_out();
    CHECK(feed_frame(1, 0x4 | 0x1, id, blk, o) == 0); /* trailers */
    CHECK(EV.nclosed == 1 && EV.closed[0] == id && EV.closed_err[0] == 0);
    CHECK(!nbl_h2p_stream_open(H, id));
    /* our side is cancelled with RST_STREAM(NO_ERROR) */
    CHECK(out_frames() == 1 && FR[0].type == 3 && FR[0].id == id && !memcmp(FR[0].pl, "\0\0\0\0", 4));
    /* a late RST_STREAM from the server does not report the stream twice */
    CHECK(feed_frame(3, 0, id, "\x00\x00\x00\x00", 4) == 0 && EV.nclosed == 1);

    /* our side already ended: no RST_STREAM */
    ev_reset();
    id = open_stream(false);
    out_reset();
    CHECK(feed_frame(1, 0x4 | 0x1, id, blk, o) == 0);
    CHECK(EV.nclosed == 1 && out_frames() == 0);

    /* END_STREAM on DATA closes as well; buffered data is dropped */
    ev_reset();
    id = open_stream(true);
    uint8_t z[6] = {0, 4, 0, 0, 0, 0};
    CHECK(feed_frame(4, 0, 0, z, 6) == 0);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"pending", 7, true) == 1);
    flush_out();
    CHECK(feed_frame(0, 0x1, id, "bye", 3) == 0);
    CHECK(EV.data_end && EV.nclosed == 1 && !nbl_h2p_stream_open(H, id));
    CHECK(out_frames() == 2 && n_frames(3, id) == 1 && wu_sum(0) == 3 && wu_sum(id) == 0);

    /* RST_STREAM from the server drops buffered data too (checked by LeakSanitizer) */
    ev_reset();
    id = open_stream(true);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"pending", 7, false) == 1);
    CHECK(feed_frame(3, 0, id, "\x00\x00\x00\x02", 4) == 0 && EV.nclosed == 1 && EV.closed_err[0] == 2);
    /* and nbl_h2p_free() frees what is still buffered */
    id = open_stream(true);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"pending", 7, false) == 1);
}

/* F7: PUSH_PROMISE is a connection error; HEADERS on server-initiated streams are ignored */
static void test_push(void)
{
    setup();
    uint32_t id = open_stream(true);
    uint8_t pp[5] = {0, 0, 0, 2, 0x88};
    CHECK(feed_frame(5, 0x4, id, pp, 5) < 0);
    CHECK(H->dead && EV.errors == 1);

    setup();
    id = open_stream(true);
    CHECK(feed_frame(1, 0x0, 2, "\x88", 1) == 0);    /* stream 2: not ours */
    CHECK(feed_frame(9, 0x0, 2, "\x89", 1) == 0);    /* its CONTINUATIONs are accepted */
    CHECK(feed_frame(9, 0x4, 2, NULL, 0) == 0);
    CHECK(ev_streams == 0 && EV.errors == 0);
    CHECK(feed_frame(1, 0x4, id, "\x88", 1) == 0 && ev_has(id, ":status=200"));
    CHECK(feed_frame(0, 0, 2, "xx", 2) == 0); /* DATA there: only connection credit */
}

/* F8: half-close without data is an empty DATA frame with END_STREAM */
static void test_half_close(void)
{
    setup();
    uint32_t id = open_stream(true);
    CHECK(nbl_h2p_send_data(H, id, NULL, 0, true) == 0);
    CHECK(out_frames() == 1 && FR[0].type == 0 && FR[0].len == 0 && FR[0].flags == 0x1 && FR[0].id == id);
    CHECK(nbl_h2p_send_data(H, id, NULL, 0, true) < 0);
    CHECK(nbl_h2p_end_stream(H, id) < 0);
    CHECK(nbl_h2p_stream_open(H, id)); /* the server has not ended it yet */

    /* also with a zero window: flow control does not apply to empty frames */
    uint8_t z[6] = {0, 4, 0, 0, 0, 0};
    CHECK(feed_frame(4, 0, 0, z, 6) == 0);
    id = open_stream(true);
    CHECK(nbl_h2p_end_stream(H, id) == 0);
    CHECK(out_frames() == 1 && FR[0].type == 0 && FR[0].len == 0 && (FR[0].flags & 0x1));

    /* data waiting for the window: END_STREAM follows it */
    id = open_stream(true);
    CHECK(nbl_h2p_send_data(H, id, (const uint8_t *)"abc", 3, false) == 1);
    CHECK(nbl_h2p_end_stream(H, id) == 1);
    CHECK(out_frames() == 0);
    uint8_t s3[6] = {0, 4, 0, 0, 0, 3};
    CHECK(feed_frame(4, 0, 0, s3, 6) == 0);
    CHECK(out_frames() == 2 && n_frames(4, 0) == 1 && n_frames(0, id) == 1); /* SETTINGS ACK, DATA */
    for (int i = 0; i < NFR; i++) {
        if (FR[i].type == 0 && FR[i].id == id) {
            CHECK(FR[i].len == 3 && (FR[i].flags & 0x1));
        }
    }
}

/* GOAWAY: full error code and last stream ID, length checked */
static void test_goaway(void)
{
    setup();
    uint8_t ga[12] = {0x80, 0, 0, 5, 0, 0, 0x01, 0x02, 'd', 'b', 'g', '!'};
    CHECK(feed_frame(7, 0, 0, ga, sizeof(ga)) == 0);
    CHECK(EV.goaway == 1 && EV.goaway_last == 5 && EV.goaway_err == 0x102);
    uint32_t id;
    nbl_h2p_hdr_t h1[] = {{":method", "POST"}};
    CHECK(nbl_h2p_open_stream(H, h1, 1, true, &id) < 0); /* no new streams after GOAWAY */
    setup();
    CHECK(feed_frame(7, 0, 0, ga, 4) < 0);
    setup();
    CHECK(feed_frame(7, 0, 1, ga, 8) < 0);
}

/* RFC 9113 tightening: preface, header block interruptions, PRIORITY length */
static void test_rfc_checks(void)
{
    setup_fresh();
    CHECK(feed_frame(6, 0, 0, "12345678", 8) < 0); /* first frame must be SETTINGS */
    setup_fresh();
    CHECK(feed_frame(4, 0x1, 0, NULL, 0) < 0); /* ... and not a SETTINGS ACK */

    setup();
    CHECK(feed_frame(1, 0x0, 1, "\x88", 1) == 0);
    CHECK(feed_frame(6, 0, 0, "12345678", 8) < 0); /* PING inside a header block */
    setup();
    CHECK(feed_frame(1, 0x0, 1, "\x88", 1) == 0);
    CHECK(feed_frame(9, 0x4, 3, NULL, 0) < 0); /* CONTINUATION for another stream */
    setup();
    CHECK(feed_frame(9, 0x4, 1, NULL, 0) < 0); /* CONTINUATION without HEADERS */
    setup();
    CHECK(feed_frame(1, 0x0, 1, "\x88", 1) == 0);
    CHECK(feed_frame(0xfa, 0, 0, NULL, 0) < 0); /* unknown frame type inside a header block */
    setup();
    CHECK(feed_frame(0xfa, 0, 0, "abc", 3) == 0); /* ... and outside: ignored */

    setup();
    CHECK(feed_frame(2, 0, 1, "\x00\x00\x00\x03\x10", 5) == 0);
    CHECK(feed_frame(2, 0, 1, "\x00\x00\x00\x03", 4) < 0);
    setup();
    CHECK(feed_frame(2, 0, 0, "\x00\x00\x00\x03\x10", 5) < 0);
}

/* F13: request headers too large for the encoder buffer fail cleanly */
static void test_encode_bounds(void)
{
    setup();
    char *v = repeat('v', 2000);
    nbl_h2p_hdr_t big[] = {{":method", "POST"}, {"x-big", v}};
    uint32_t id;
    CHECK(nbl_h2p_open_stream(H, big, 2, true, &id) < 0);
    CHECK(!nbl_h2p_want_write(H));
    v[900] = 0; /* fits */
    CHECK(nbl_h2p_open_stream(H, big, 2, true, &id) == 0 && id == 1); /* the failed try used no ID */
    CHECK(out_frames() == 1 && FR[0].type == 1 && FR[0].len > 900);
    free(v);
    nbl_h2p_hdr_t h1[] = {{":method", "POST"}};
    for (int i = 1; i < 8; i++) { /* no slot leaked */
        CHECK(nbl_h2p_open_stream(H, h1, 1, true, &id) == 0);
    }
}

int main(void)
{
    test_hpack_rfc();
    test_frames();
    test_send_flow();
    test_stream_ids();
    test_continuation();
    test_burst();
    test_send_queue();
    test_big_headers();
    test_hpack_lengths();
    test_settings();
    test_window_settings();
    test_recv_credit();
    test_remote_end();
    test_push();
    test_half_close();
    test_goaway();
    test_rfc_checks();
    test_encode_bounds();
    nbl_h2p_free(H);
    if (fails) {
        printf("test_h2p: %d of %d checks FAILED\n", fails, checks);
        return 1;
    }
    printf("test_h2p: all %d checks passed\n", checks);
    return 0;
}
