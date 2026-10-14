// SPDX-License-Identifier: MIT
#include "nbl_h2p.h"

#include <limits.h>

#ifndef ESP_PLATFORM
static size_t strlcpy(char *dst, const char *src, size_t cap)
{
    size_t n = strlen(src);
    if (cap) {
        size_t c = n < cap - 1 ? n : cap - 1;
        memcpy(dst, src, c);
        dst[c] = 0;
    }
    return n;
}
#endif

#include "nbl_huff.inc"

/* every field that is not dropped (name <= 127, value <= 383 bytes, integers <= 10 bytes)
   fits into the header block buffer, so decoding always makes progress */
_Static_assert(NBL_H2P_MAX_HDRBLK >= 600, "header block buffer too small");
_Static_assert(NBL_H2P_RESERVE >= 64 && NBL_H2P_RESERVE <= NBL_H2P_OUT_CAP / 2, "send queue reserve");

/* ---------------- HPACK: static table (RFC 7541, Appendix A) ---------------- */

static const struct {
    const char *name;
    const char *value;
} STATIC_TABLE[61] = {
    {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"}, {":path", "/index.html"},
    {":scheme", "http"}, {":scheme", "https"}, {":status", "200"}, {":status", "204"}, {":status", "206"},
    {":status", "304"}, {":status", "400"}, {":status", "404"}, {":status", "500"}, {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"}, {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""},
    {"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""}, {"authorization", ""},
    {"cache-control", ""}, {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""},
    {"content-length", ""}, {"content-location", ""}, {"content-range", ""}, {"content-type", ""},
    {"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""}, {"from", ""}, {"host", ""},
    {"if-match", ""}, {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""},
    {"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""}, {"location", ""},
    {"max-forwards", ""}, {"proxy-authenticate", ""}, {"proxy-authorization", ""}, {"range", ""},
    {"referer", ""}, {"refresh", ""}, {"retry-after", ""}, {"server", ""},
    {"set-cookie", ""}, {"strict-transport-security", ""}, {"transfer-encoding", ""}, {"user-agent", ""},
    {"vary", ""}, {"via", ""}, {"www-authenticate", ""},
};

/* ---------------- small encoding helpers ---------------- */

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)(v >> 24);
    o[1] = (uint8_t)(v >> 16);
    o[2] = (uint8_t)(v >> 8);
    o[3] = (uint8_t)v;
}

static size_t put_int(uint8_t *o, uint64_t v, unsigned prefix_bits, uint8_t first)
{
    uint64_t max = (1u << prefix_bits) - 1;
    size_t n = 0;
    if (v < max) {
        o[n++] = first | (uint8_t)v;
        return n;
    }
    o[n++] = first | (uint8_t)max;
    v -= max;
    while (v >= 0x80) {
        o[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    o[n++] = (uint8_t)v;
    return n;
}

static size_t put_str(uint8_t *o, const char *s)
{
    size_t len = strlen(s);
    size_t n = put_int(o, len, 7, 0); /* we never Huffman-encode on send */
    memcpy(o + n, s, len);
    return n + len;
}

/* HPACK integer (RFC 7541 5.1): 0 = ok, 1 = incomplete (*p unchanged), -1 = too large */
static int get_int(const uint8_t **p, const uint8_t *end, unsigned prefix_bits, uint64_t *out)
{
    const uint8_t *q = *p;
    if (q >= end) {
        return 1;
    }
    uint64_t max = (1u << prefix_bits) - 1;
    uint64_t v = *q++ & max;
    if (v == max) {
        for (unsigned sh = 0;; sh += 7) {
            if (sh > 56) {
                return -1;
            }
            if (q >= end) {
                return 1;
            }
            uint8_t b = *q++;
            v += (uint64_t)(b & 0x7f) << sh;
            if (!(b & 0x80)) {
                break;
            }
        }
    }
    *p = q;
    *out = v;
    return 0;
}

/* ---------------- Huffman decoding ---------------- */

/* 0 = ok, -1 = invalid code, -2 = more than cap bytes */
static int huff_decode(const uint8_t *in, size_t inlen, uint8_t *out, size_t cap, size_t *outlen)
{
    uint64_t acc = 0;
    int bits = 0;
    size_t pos = 0, o = 0;
    for (;;) {
        if (bits < 30 && pos < inlen) {
            acc = (acc << 8) | in[pos++];
            bits += 8;
        }
        int sym = -1, blen = 0;
        uint32_t code = 0;
        for (blen = 5; blen <= 30; blen++) {
            if (bits < blen) {
                break;
            }
            code = (uint32_t)((acc >> (bits - blen)) & ((1ULL << blen) - 1));
            /* table is in symbol order: linear search for (bits, code) */
            for (int j = 0; j < 257; j++) {
                if (nbl_huff_table[j].bits == blen && nbl_huff_table[j].code == code) {
                    sym = j;
                    break;
                }
            }
            if (sym >= 0) {
                break;
            }
        }
        if (sym < 0) {
            if (bits >= 30) {
                return -1; /* full accumulator but no symbol: invalid data */
            }
            if (pos >= inlen) {
                break; /* leftover bits are checked below */
            }
            continue;
        }
        if (sym == 256) {
            return -1; /* EOS inside a string */
        }
        if (o >= cap) {
            return -2;
        }
        out[o++] = (uint8_t)sym;
        bits -= blen;
        acc &= (1ULL << bits) - 1;
    }
    /* RFC 7541 5.2: padding must be shorter than 8 bits and all ones (EOS prefix) */
    if (bits > 7 || (bits && (acc & ((1u << bits) - 1)) != ((1u << bits) - 1))) {
        return -1;
    }
    *outlen = o;
    return 0;
}

/* ---------------- HPACK decoding ---------------- */

/* String literal (RFC 7541 5.2) into dst, NUL-terminated. 0 = ok, 1 = incomplete (*p
   unchanged), 2 = longer than dst: dropped (skipped; a part not received yet is left in
   h->hp_skip), -1 = invalid. */
static int get_str(nbl_h2p_t *h, const uint8_t **p, const uint8_t *end, char *dst, size_t cap)
{
    const uint8_t *q = *p;
    if (q >= end) {
        return 1;
    }
    bool huff = *q & 0x80;
    uint64_t len;
    int r = get_int(&q, end, 7, &len);
    if (r) {
        return r;
    }
    size_t avail = (size_t)(end - q);
    if (len >= cap) {
        if (len > avail) {
            h->hp_skip = len - avail;
            *p = end;
        } else {
            *p = q + len;
        }
        return 2;
    }
    if (len > avail) {
        return 1;
    }
    size_t n = (size_t)len;
    if (huff) {
        r = huff_decode(q, (size_t)len, (uint8_t *)dst, cap - 1, &n);
        if (r == -2) {
            *p = q + len;
            return 2;
        }
        if (r < 0) {
            return -1;
        }
    } else {
        memcpy(dst, q, n);
    }
    dst[n] = 0;
    *p = q + len;
    return 0;
}

/* Decodes the complete header fields at the start of h->hdrblk and reports them. Returns the
   number of bytes consumed (an incomplete field stays for the next fragment), -1 = invalid
   (COMPRESSION_ERROR). Fields that do not fit name[]/value[] are dropped: we only need short
   ones (:status, content-type, grpc-status, grpc-message, x-wiretrustee-peer-registered). */
static int hpack_decode(nbl_h2p_t *h)
{
    const uint8_t *p = h->hdrblk;
    const uint8_t *end = h->hdrblk + h->hdrblk_len;
    char name[128], value[384];
    while (p < end && !h->hp_skip) {
        const uint8_t *field = p;
        uint64_t idx;
        int r;
        if (h->hp_skip_value) { /* the oversized name has been skipped: drop the value too */
            r = get_str(h, &p, end, value, 1);
            if (r == 1) {
                break;
            }
            if (r < 0) {
                return -1;
            }
            h->hp_skip_value = false;
            continue;
        }
        bool drop = false;
        if (*p & 0x80) { /* indexed header field */
            r = get_int(&p, end, 7, &idx);
            if (r == 1) {
                break;
            }
            if (r < 0 || idx == 0 || idx > 61) {
                return -1; /* our dynamic table is disabled (HEADER_TABLE_SIZE=0) */
            }
            strlcpy(name, STATIC_TABLE[idx - 1].name, sizeof(name));
            strlcpy(value, STATIC_TABLE[idx - 1].value, sizeof(value));
        } else if ((*p & 0xe0) == 0x20) { /* dynamic table size update: 0 only, block start only */
            r = get_int(&p, end, 5, &idx);
            if (r == 1) {
                break;
            }
            if (r < 0 || idx != 0 || h->hp_started) {
                return -1;
            }
            continue;
        } else { /* literal; "with incremental indexing" is read, but there is no table */
            unsigned pfx = (*p & 0x40) ? 6 : 4;
            r = get_int(&p, end, pfx, &idx);
            if (r == 1) {
                break;
            }
            if (r < 0 || idx > 61) {
                return -1;
            }
            if (idx) { /* indexed name (static table) */
                strlcpy(name, STATIC_TABLE[idx - 1].name, sizeof(name));
            } else { /* literal name */
                r = get_str(h, &p, end, name, sizeof(name));
                if (r < 0) {
                    return -1;
                }
                if (r == 1) {
                    p = field;
                    break;
                }
                drop = r == 2;
                if (h->hp_skip) { /* the rest of the name follows, then the value */
                    h->hp_skip_value = true;
                    h->hp_started = true;
                    break;
                }
            }
            r = get_str(h, &p, end, value, sizeof(value));
            if (r < 0) {
                return -1;
            }
            if (r == 1) {
                p = field;
                break;
            }
            drop = drop || r == 2;
        }
        h->hp_started = true;
        if (!drop && !h->hdrblk_ignore && h->cb.on_header) {
            h->cb.on_header(h->ctx, h->hdrblk_stream, name, value);
        }
    }
    return (int)(p - h->hdrblk);
}

/* Takes the next piece of a header block (HEADERS/CONTINUATION payload) and decodes it. */
static int hdr_feed(nbl_h2p_t *h, const uint8_t *p, size_t len)
{
    while (len) {
        size_t k;
        if (h->hp_skip) { /* rest of an oversized string */
            k = h->hp_skip < len ? (size_t)h->hp_skip : len;
            h->hp_skip -= k;
        } else {
            k = sizeof(h->hdrblk) - h->hdrblk_len;
            if (k > len) {
                k = len;
            }
            memcpy(h->hdrblk + h->hdrblk_len, p, k);
            h->hdrblk_len += k;
            int used = hpack_decode(h);
            if (used < 0 || (used == 0 && h->hdrblk_len == sizeof(h->hdrblk))) {
                return -1;
            }
            h->hdrblk_len -= (size_t)used;
            memmove(h->hdrblk, h->hdrblk + used, h->hdrblk_len);
        }
        p += k;
        len -= k;
    }
    return 0;
}

/* ---------------- send queue ---------------- */

bool nbl_h2p_want_write(const nbl_h2p_t *h)
{
    return h->out_len > 0;
}

/* Queues one frame, all or nothing. HEADERS and DATA (ctrl = false) leave NBL_H2P_RESERVE
   bytes free for the control frames that answer received frames. */
static int send_frame(nbl_h2p_t *h, uint8_t type, uint8_t flags, uint32_t id, const void *payload, size_t len,
                      bool ctrl)
{
    size_t cap = ctrl ? NBL_H2P_OUT_CAP : NBL_H2P_OUT_CAP - NBL_H2P_RESERVE;
    if (len > NBL_H2P_MAX_FRAME || h->out_len + 9 + len > cap) {
        return -1;
    }
    uint8_t *o = h->out + h->out_len;
    o[0] = (uint8_t)(len >> 16);
    o[1] = (uint8_t)(len >> 8);
    o[2] = (uint8_t)len;
    o[3] = type;
    o[4] = flags;
    put32(o + 5, id & 0x7fffffff);
    if (len) {
        memcpy(o + 9, payload, len);
    }
    h->out_len += 9 + len;
    return 0;
}

/* Control frames must not get lost: no room for one is a connection error. */
static int ctrl_frame(nbl_h2p_t *h, uint8_t type, uint8_t flags, uint32_t id, const void *payload, size_t len)
{
    if (send_frame(h, type, flags, id, payload, len, true) < 0) {
        h->dead = true;
        return -1;
    }
    return 0;
}

/* ---------------- Streams ---------------- */

static nbl_h2p_stream_t *stream_find(const nbl_h2p_t *h, uint32_t id)
{
    /* open addressing with linear probing; the stream ID is stored in the entry */
    uint32_t slot = (id / 2) % h->streams_cap;
    for (uint32_t i = 0; i < h->streams_cap; i++) {
        nbl_h2p_stream_t *s = &h->streams[(slot + i) % h->streams_cap];
        if (s->used && s->id == id) {
            return s;
        }
    }
    return NULL;
}

static nbl_h2p_stream_t *stream_new(nbl_h2p_t *h, uint32_t id)
{
    uint32_t slot = (id / 2) % h->streams_cap;
    for (uint32_t i = 0; i < h->streams_cap; i++) {
        nbl_h2p_stream_t *s = &h->streams[(slot + i) % h->streams_cap];
        if (!s->used) {
            memset(s, 0, sizeof(*s));
            s->used = true;
            s->id = id;
            s->send_window = h->peer_init_window;
            return s;
        }
    }
    return NULL;
}

static void stream_free(nbl_h2p_stream_t *s)
{
    free(s->pending);
    memset(s, 0, sizeof(*s));
}

bool nbl_h2p_stream_open(const nbl_h2p_t *h, uint32_t id)
{
    return stream_find(h, id) != NULL;
}

bool nbl_h2p_can_send(const nbl_h2p_t *h, uint32_t id)
{
    const nbl_h2p_stream_t *s = stream_find(h, id);
    return s && !s->local_ended && !s->pending_end && s->pending_off == s->pending_len && s->send_window > 0 &&
           h->conn_send_window > 0;
}

/* ---------------- flow control ---------------- */

/* Moves DATA from (*d, *n) into the send queue as far as the flow-control windows and the
   queue allow. With end, END_STREAM goes on the frame with the last byte (or on an empty
   frame: flow control does not apply to it). */
static void queue_data(nbl_h2p_t *h, nbl_h2p_stream_t *s, const uint8_t **d, size_t *n, bool end)
{
    const size_t lim = NBL_H2P_OUT_CAP - NBL_H2P_RESERVE;
    while (!s->local_ended && h->out_len + 9 <= lim) {
        int32_t win = h->conn_send_window < s->send_window ? h->conn_send_window : s->send_window;
        size_t chunk = lim - 9 - h->out_len;
        if (chunk > *n) {
            chunk = *n;
        }
        if (chunk > h->peer_max_frame) {
            chunk = h->peer_max_frame;
        }
        if (win <= 0) {
            chunk = 0;
        } else if (chunk > (size_t)win) {
            chunk = (size_t)win;
        }
        bool fin = end && chunk == *n;
        if (!chunk && !fin) {
            return;
        }
        if (send_frame(h, 0, fin ? 0x1 : 0, s->id, *d, chunk, false) < 0) {
            return;
        }
        if (chunk) {
            h->conn_send_window -= (int32_t)chunk;
            s->send_window -= (int32_t)chunk;
            *d += chunk;
            *n -= chunk;
        }
        if (fin) {
            s->local_ended = true;
        }
    }
}

/* Received DATA is consumed at once, so its size goes straight back as window credit. */
static int add_credit(uint32_t *credit, size_t n)
{
    if (n > 0x7fffffff - *credit) {
        return -1; /* far more than the windows we granted: FLOW_CONTROL_ERROR */
    }
    *credit += (uint32_t)n;
    return 0;
}

static int wu_frame(nbl_h2p_t *h, uint32_t id, uint32_t *credit)
{
    uint8_t wu[4];
    put32(wu, *credit);
    if (send_frame(h, 8, 0, id, wu, 4, true) < 0) {
        return -1; /* queue full: the credit waits for the next pump */
    }
    *credit = 0;
    return 0;
}

/* Fills the send queue from buffered work: WINDOW_UPDATE credit first, then buffered DATA. */
static void pump(nbl_h2p_t *h)
{
    if (h->conn_credit && wu_frame(h, 0, &h->conn_credit) < 0) {
        return;
    }
    for (uint32_t i = 0; i < h->streams_cap; i++) {
        nbl_h2p_stream_t *s = &h->streams[i];
        if (s->used && s->recv_credit && wu_frame(h, s->id, &s->recv_credit) < 0) {
            return;
        }
    }
    for (uint32_t i = 0; i < h->streams_cap; i++) {
        nbl_h2p_stream_t *s = &h->streams[i];
        if (!s->used || s->local_ended || (s->pending_off == s->pending_len && !s->pending_end)) {
            continue;
        }
        const uint8_t *d = s->pending ? s->pending + s->pending_off : NULL;
        size_t n = s->pending_len - s->pending_off;
        queue_data(h, s, &d, &n, s->pending_end);
        s->pending_off = s->pending_len - n;
        if (!n) {
            free(s->pending);
            s->pending = NULL;
            s->pending_len = s->pending_off = 0;
        }
        if (s->local_ended) {
            s->pending_end = false;
        }
    }
}

size_t nbl_h2p_output(nbl_h2p_t *h, uint8_t *dst, size_t cap)
{
    size_t n = h->out_len < cap ? h->out_len : cap;
    if (n) {
        memcpy(dst, h->out, n);
        memmove(h->out, h->out + n, h->out_len - n);
        h->out_len -= n;
    }
    pump(h); /* buffered DATA and window updates move up */
    return n;
}

/* ---------------- public actions ---------------- */

int nbl_h2p_init(nbl_h2p_t *h, const nbl_h2p_cb_t *cb, void *ctx, nbl_h2p_stream_t *streams, uint32_t cap)
{
    memset(h, 0, sizeof(*h));
    if (!streams || !cap) {
        return -1;
    }
    memset(streams, 0, cap * sizeof(*streams));
    h->cb = *cb;
    h->ctx = ctx;
    h->streams = streams;
    h->streams_cap = cap;
    h->conn_send_window = 65535;
    h->peer_init_window = 65535;
    h->peer_max_frame = 16384;
    h->next_stream = 1;
    return 0;
}

void nbl_h2p_free(nbl_h2p_t *h)
{
    for (uint32_t i = 0; i < h->streams_cap; i++) {
        if (h->streams[i].used) {
            stream_free(&h->streams[i]);
        }
    }
}

int nbl_h2p_start(nbl_h2p_t *h)
{
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (h->out_len + 24 > NBL_H2P_OUT_CAP) {
        return -1;
    }
    memcpy(h->out + h->out_len, preface, 24);
    h->out_len += 24;
    /* SETTINGS: dynamic table off, windows large enough for big network maps. Header lists of
       any size can be decoded (oversized fields are dropped); the announced limit only keeps a
       server from sending absurd ones. */
    static const struct {
        uint16_t k;
        uint32_t v;
    } set[] = {
        {0x1, 0},                   /* HEADER_TABLE_SIZE = 0 */
        {0x2, 0},                   /* ENABLE_PUSH = 0 */
        {0x4, 65535 * 16},          /* INITIAL_WINDOW_SIZE ~1 MB */
        {0x6, NBL_H2P_MAX_HDRLIST}, /* MAX_HEADER_LIST_SIZE */
    };
    uint8_t pl[sizeof(set) / sizeof(set[0]) * 6];
    size_t o = 0;
    for (size_t i = 0; i < sizeof(set) / sizeof(set[0]); i++) {
        pl[o++] = (uint8_t)(set[i].k >> 8);
        pl[o++] = (uint8_t)set[i].k;
        put32(pl + o, set[i].v);
        o += 4;
    }
    if (ctrl_frame(h, 4, 0, 0, pl, o) < 0) { /* SETTINGS */
        return -1;
    }
    /* enlarge the connection window so a Sync stream does not run dry early */
    uint8_t wu[4];
    put32(wu, 65535 * 16);
    return ctrl_frame(h, 8, 0, 0, wu, 4); /* connection-level WINDOW_UPDATE */
}

/* HPACK-encodes a request header list. Returns the length, -1 if it does not fit into cap. */
static int encode_headers(uint8_t *out, size_t cap, const nbl_h2p_hdr_t *hdrs, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        /* upper bound for one field: index byte(s) plus two length prefixes (<= 11 bytes each) */
        size_t nl = strlen(hdrs[i].name), vl = strlen(hdrs[i].value);
        if (nl > cap || vl > cap || cap - o < 32 + nl + vl) {
            return -1;
        }
        /* exact static-table matches are sent as indexed fields */
        int idx = -1;
        for (int j = 0; j < 61; j++) {
            if (!strcmp(hdrs[i].name, STATIC_TABLE[j].name) && !strcmp(hdrs[i].value, STATIC_TABLE[j].value) &&
                STATIC_TABLE[j].value[0]) {
                idx = j + 1;
                break;
            }
        }
        if (idx > 0) {
            o += put_int(out + o, (uint64_t)idx, 7, 0x80);
            continue;
        }
        /* known name? -> literal without indexing, indexed name */
        int nidx = -1;
        for (int j = 0; j < 61; j++) {
            if (!strcmp(hdrs[i].name, STATIC_TABLE[j].name)) {
                nidx = j + 1;
                break;
            }
        }
        if (nidx > 0) {
            o += put_int(out + o, (uint64_t)nidx, 4, 0x00);
        } else {
            o += put_int(out + o, 0, 4, 0x00);
            o += put_str(out + o, hdrs[i].name);
        }
        o += put_str(out + o, hdrs[i].value);
    }
    return (int)o;
}

int nbl_h2p_open_stream(nbl_h2p_t *h, const nbl_h2p_hdr_t *hdrs, size_t n, bool has_body, uint32_t *id_out)
{
    if (h->dead || h->next_stream > 0x7fffffff) {
        return -1;
    }
    uint32_t id = h->next_stream;
    nbl_h2p_stream_t *s = stream_new(h, id);
    if (!s) {
        return -1;
    }
    uint8_t blk[1024];
    int bl = encode_headers(blk, sizeof(blk), hdrs, n);
    if (bl < 0 || send_frame(h, 1, has_body ? 0x4 : 0x4 | 0x1, id, blk, (size_t)bl, false) < 0) {
        s->used = false;
        return -1;
    }
    h->next_stream += 2;
    s->local_ended = !has_body;
    *id_out = id;
    return 0;
}

int nbl_h2p_send_data(nbl_h2p_t *h, uint32_t id, const uint8_t *data, size_t len, bool end)
{
    nbl_h2p_stream_t *s = stream_find(h, id);
    if (!s || s->local_ended || s->pending_end) {
        return -1;
    }
    if (len) { /* append to what is waiting already; the pump queues as much as it can */
        size_t left = s->pending_len - s->pending_off;
        uint8_t *p = malloc(left + len);
        if (!p) {
            return -1;
        }
        if (left) {
            memcpy(p, s->pending + s->pending_off, left);
        }
        memcpy(p + left, data, len);
        free(s->pending);
        s->pending = p;
        s->pending_len = left + len;
        s->pending_off = 0;
    }
    s->pending_end = end;
    pump(h);
    return s->pending_off != s->pending_len || s->pending_end ? 1 : 0;
}

int nbl_h2p_end_stream(nbl_h2p_t *h, uint32_t id)
{
    return nbl_h2p_send_data(h, id, NULL, 0, true);
}

int nbl_h2p_reset(nbl_h2p_t *h, uint32_t id)
{
    nbl_h2p_stream_t *s = stream_find(h, id);
    if (!s) {
        return 0; /* not open (any more): nothing to cancel */
    }
    stream_free(s);
    return ctrl_frame(h, 3, 0, id, "\x00\x00\x00\x08", 4); /* CANCEL */
}

int nbl_h2p_ping(nbl_h2p_t *h)
{
    return send_frame(h, 6, 0, 0, "nbl-ping", 8, true);
}

/* ---------------- receive ---------------- */

/* The server ended the stream (END_STREAM). The gRPC call is complete then, so the slot is
   freed even if our side is still open; that side is cancelled with RST_STREAM(NO_ERROR),
   as grpc-go does. */
static int remote_end(nbl_h2p_t *h, uint32_t id)
{
    nbl_h2p_stream_t *s = stream_find(h, id);
    if (!s) {
        return 0; /* unknown, or reset from a callback meanwhile */
    }
    bool rst = !s->local_ended;
    stream_free(s);
    if (rst && ctrl_frame(h, 3, 0, id, "\x00\x00\x00\x00", 4) < 0) {
        return -1;
    }
    if (h->cb.on_stream_closed) {
        h->cb.on_stream_closed(h->ctx, id, 0);
    }
    return 0;
}

static int rx_data(nbl_h2p_t *h, uint8_t flags, uint32_t id, const uint8_t *pl, size_t len)
{
    if (id == 0) {
        return -1;
    }
    size_t flow = len; /* flow control counts the whole payload, padding included */
    if (flags & 0x8) { /* PADDED */
        if (len < 1 || pl[0] >= len) {
            return -1;
        }
        len -= 1 + (size_t)pl[0];
        pl++;
    }
    if (add_credit(&h->conn_credit, flow) < 0) {
        return -1;
    }
    nbl_h2p_stream_t *s = stream_find(h, id);
    if (!s) {
        return 0; /* unknown or closed stream (e.g. after our RST_STREAM): connection credit only */
    }
    bool end = flags & 0x1;
    if (!end && add_credit(&s->recv_credit, flow) < 0) {
        return -1;
    }
    if (h->cb.on_data) {
        h->cb.on_data(h->ctx, id, pl, len, end);
    }
    return end ? remote_end(h, id) : 0; /* the callback may have reset the stream */
}

static int rx_headers(nbl_h2p_t *h, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *pl, size_t len)
{
    if (type == 1) { /* HEADERS: starts a header block */
        if (id == 0) {
            return -1;
        }
        if (flags & 0x8) { /* PADDED */
            if (len < 1 || pl[0] >= len) {
                return -1;
            }
            len -= 1 + (size_t)pl[0];
            pl++;
        }
        if (flags & 0x20) { /* PRIORITY: 5 bytes, ignored */
            if (len < 5) {
                return -1;
            }
            pl += 5;
            len -= 5;
        }
        h->in_header_block = true;
        h->hdrblk_stream = id;
        h->hdrblk_flags = flags;
        h->hdrblk_ignore = id % 2 == 0; /* server-initiated stream (push is off): not reported */
        h->hdrblk_len = 0;
        h->hp_skip = 0;
        h->hp_skip_value = false;
        h->hp_started = false;
    } else if (!h->in_header_block || id != h->hdrblk_stream) { /* CONTINUATION */
        return -1;
    }
    if (hdr_feed(h, pl, len) < 0) {
        return -1;
    }
    if (!(flags & 0x4)) { /* no END_HEADERS -> CONTINUATION follows */
        return 0;
    }
    h->in_header_block = false;
    if (h->hdrblk_len || h->hp_skip || h->hp_skip_value) {
        return -1; /* the block ends inside a field */
    }
    if (h->hdrblk_ignore) {
        return 0;
    }
    bool end_stream = h->hdrblk_flags & 0x1;
    if (h->cb.on_headers_done) {
        h->cb.on_headers_done(h->ctx, id, end_stream);
    }
    return end_stream ? remote_end(h, id) : 0;
}

static int rx_settings(nbl_h2p_t *h, uint8_t flags, uint32_t id, const uint8_t *pl, size_t len)
{
    if (id != 0) {
        return -1;
    }
    if (flags & 0x1) {
        return len == 0 ? 0 : -1; /* ACK */
    }
    if (len % 6) {
        return -1;
    }
    for (size_t i = 0; i < len; i += 6) {
        uint16_t k = (uint16_t)(pl[i] << 8 | pl[i + 1]);
        uint32_t v = get32(pl + i + 2);
        if (k == 0x4) { /* INITIAL_WINDOW_SIZE: changes the window of every open stream */
            if (v > 0x7fffffff) {
                return -1; /* FLOW_CONTROL_ERROR */
            }
            int64_t delta = (int64_t)v - h->peer_init_window;
            for (uint32_t j = 0; j < h->streams_cap; j++) {
                nbl_h2p_stream_t *s = &h->streams[j];
                if (!s->used) {
                    continue;
                }
                int64_t w = s->send_window + delta;
                if (w > 0x7fffffff || w < -0x7fffffff) {
                    return -1; /* FLOW_CONTROL_ERROR (RFC 9113 6.9.2) */
                }
                s->send_window = (int32_t)w;
            }
            h->peer_init_window = (int32_t)v;
        } else if (k == 0x5) { /* MAX_FRAME_SIZE */
            if (v < 16384 || v > 16777215) {
                return -1; /* PROTOCOL_ERROR */
            }
            h->peer_max_frame = v;
        }
    }
    return ctrl_frame(h, 4, 0x1, 0, NULL, 0); /* ACK; grown windows are used by the pump */
}

static int handle_frame(nbl_h2p_t *h, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *pl, size_t len)
{
    if (!h->preface_ok) { /* the server's connection preface is a SETTINGS frame */
        if (type != 4 || (flags & 0x1)) {
            return -1;
        }
        h->preface_ok = true;
    }
    if (h->in_header_block && type != 9) {
        return -1; /* only CONTINUATION may follow an unfinished header block */
    }
    switch (type) {
    case 0: /* DATA */
        return rx_data(h, flags, id, pl, len);
    case 1: /* HEADERS */
    case 9: /* CONTINUATION */
        return rx_headers(h, type, flags, id, pl, len);
    case 2: /* PRIORITY: ignored */
        return id == 0 || len != 5 ? -1 : 0;
    case 3: { /* RST_STREAM */
        if (len != 4 || id == 0) {
            return -1;
        }
        nbl_h2p_stream_t *s = stream_find(h, id);
        if (s) {
            stream_free(s);
            if (h->cb.on_stream_closed) {
                h->cb.on_stream_closed(h->ctx, id, get32(pl));
            }
        }
        return 0;
    }
    case 4: /* SETTINGS */
        return rx_settings(h, flags, id, pl, len);
    case 5: /* PUSH_PROMISE: we sent ENABLE_PUSH = 0 */
        return -1;
    case 6: /* PING */
        if (len != 8 || id != 0) {
            return -1;
        }
        return (flags & 0x1) ? 0 : ctrl_frame(h, 6, 0x1, 0, pl, 8); /* ACK with the same payload */
    case 7: /* GOAWAY: last stream ID, error code, debug data */
        if (len < 8 || id != 0) {
            return -1;
        }
        h->dead = true;
        if (h->cb.on_goaway) {
            h->cb.on_goaway(h->ctx, get32(pl) & 0x7fffffff, get32(pl + 4));
        }
        return 0;
    case 8: { /* WINDOW_UPDATE */
        if (len != 4) {
            return -1;
        }
        uint32_t inc = get32(pl) & 0x7fffffff;
        if (inc == 0) {
            return -1;
        }
        int32_t *w = &h->conn_send_window;
        if (id) {
            nbl_h2p_stream_t *s = stream_find(h, id);
            if (!s) {
                return 0; /* closed stream */
            }
            w = &s->send_window;
        }
        if ((int64_t)*w + inc > 0x7fffffff) {
            return -1; /* FLOW_CONTROL_ERROR */
        }
        *w += (int32_t)inc;
        return 0; /* buffered DATA goes out with the pump at the end of nbl_h2p_input() */
    }
    default:
        return 0; /* ignore unknown frame types (RFC 9113 4.1) */
    }
}

static int fail(nbl_h2p_t *h, const char *why)
{
    h->dead = true;
    if (h->cb.on_error) {
        h->cb.on_error(h->ctx, why);
    }
    return -1;
}

int nbl_h2p_input(nbl_h2p_t *h, const uint8_t *data, size_t len)
{
    if (len > INT_MAX) {
        len = INT_MAX;
    }
    size_t used = 0;
    /* the answers to one frame take far less than NBL_H2P_RESERVE: go on only while that much
       is free, otherwise the caller has to send first */
    while (used < len && h->out_len <= NBL_H2P_OUT_CAP - NBL_H2P_RESERVE) {
        size_t need = 9; /* frame header, then the payload */
        if (h->rx_len >= 9) {
            need += ((size_t)h->rx[0] << 16) | ((size_t)h->rx[1] << 8) | h->rx[2];
        }
        need -= h->rx_len;
        if (need > len - used) {
            need = len - used;
        }
        memcpy(h->rx + h->rx_len, data + used, need);
        h->rx_len += need;
        used += need;
        if (h->rx_len < 9) {
            continue;
        }
        size_t fl = ((size_t)h->rx[0] << 16) | ((size_t)h->rx[1] << 8) | h->rx[2];
        if (fl > NBL_H2P_MAX_FRAME) {
            return fail(h, "frame too large");
        }
        if (h->rx_len < 9 + fl) {
            continue;
        }
        uint8_t type = h->rx[3], flags = h->rx[4];
        uint32_t id = get32(h->rx + 5) & 0x7fffffff;
        h->rx_len = 0;
        if (handle_frame(h, type, flags, id, h->rx + 9, fl) < 0) {
            return fail(h, "protocol error");
        }
    }
    pump(h); /* coalesced WINDOW_UPDATEs, DATA the new windows allow */
    return (int)used;
}
