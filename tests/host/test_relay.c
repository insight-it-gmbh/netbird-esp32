// Host tests for the pure parts of the relay transport: WebSocket framing and the handshake
// check (nbl_ws.c), relay messages and the relay URL parser (nbl_relaymsg.c).
// Plain C11, no ESP-IDF needed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nbl_relaymsg.h"
#include "nbl_ws.h"

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

#define MSG_CAP (NBL_R_MAX_MSG + 32) /* as in nbl_relay.c */
#define ACC_CAP (NBL_R_MAX_MSG + 64)

static uint8_t msg[MSG_CAP];
static uint8_t buf[ACC_CAP + 64];

/* Appends an unmasked server frame with first byte b0 and a minimal length encoding */
static size_t put_frame(uint8_t *out, uint8_t b0, const void *p, size_t n)
{
    size_t o = 0;
    out[o++] = b0;
    if (n < 126) {
        out[o++] = (uint8_t)n;
    } else {
        out[o++] = 126;
        out[o++] = (uint8_t)(n >> 8);
        out[o++] = (uint8_t)n;
    }
    if (n) {
        memcpy(out + o, p, n);
    }
    return o + n;
}

/* Feeds acc[0..len) frame by frame and returns the result of the call that does not consume
 * a whole frame (0 = incomplete, <0 = error); *last receives the last event. */
static int drain(nbl_ws_t *st, const uint8_t *acc, size_t len, nbl_ws_event_t *last)
{
    size_t off = 0;
    for (;;) {
        int n = nbl_ws_next(st, acc + off, len - off, last);
        if (n <= 0) {
            return n;
        }
        off += (size_t)n;
    }
}

static void test_lengths(void)
{
    nbl_ws_t st;
    nbl_ws_event_t ev;

    /* 64-bit lengths: 256 (not minimal) and 65536 (minimal, but above 64 KiB) are rejected,
     * and already from the first two header bytes */
    uint8_t l64a[10] = {0x82, 127, 0, 0, 0, 0, 0, 0, 1, 0};
    uint8_t l64b[10] = {0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t l64c[10] = {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0};
    nbl_ws_init(&st, msg, sizeof(msg));
    CHECK(nbl_ws_next(&st, l64a, sizeof(l64a), &ev) < 0);
    CHECK(nbl_ws_next(&st, l64b, sizeof(l64b), &ev) < 0);
    CHECK(nbl_ws_next(&st, l64c, sizeof(l64c), &ev) < 0);
    CHECK(nbl_ws_next(&st, l64b, 2, &ev) < 0);

    /* 16-bit length: 5 encoded with 126 is not minimal */
    uint8_t l16[9] = {0x82, 126, 0, 5, 'a', 'b', 'c', 'd', 'e'};
    CHECK(nbl_ws_next(&st, l16, sizeof(l16), &ev) < 0);
    /* 126 is the smallest valid 16-bit length; incomplete header and payload give 0 */
    uint8_t pay[126];
    memset(pay, 'x', sizeof(pay));
    size_t n = put_frame(buf, 0x82, pay, sizeof(pay));
    CHECK(n == 4 + 126);
    CHECK(nbl_ws_next(&st, buf, 3, &ev) == 0);
    CHECK(nbl_ws_next(&st, buf, n - 1, &ev) == 0);
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_DATA && ev.len == 126);
    /* 125 must use the 7-bit form */
    uint8_t l7[4 + 125] = {0x82, 126, 0, 125};
    CHECK(nbl_ws_next(&st, l7, sizeof(l7), &ev) < 0);
    /* the largest relay message fits */
    static uint8_t big[NBL_R_MAX_MSG];
    memset(big, 7, sizeof(big));
    n = put_frame(buf, 0x82, big, sizeof(big));
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_DATA && ev.len == sizeof(big));
}

static void test_fragments(void)
{
    nbl_ws_t st;
    nbl_ws_event_t ev;
    size_t n;

    /* continuation without a start frame */
    nbl_ws_init(&st, msg, sizeof(msg));
    n = put_frame(buf, 0x80, "abc", 3);
    CHECK(nbl_ws_next(&st, buf, n, &ev) < 0);

    /* a new data message while a fragmented one is open (with and without FIN) */
    nbl_ws_init(&st, msg, sizeof(msg));
    n = put_frame(buf, 0x02, "a", 1);
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_NEED_MORE);
    n = put_frame(buf, 0x82, "b", 1);
    CHECK(nbl_ws_next(&st, buf, n, &ev) < 0);
    n = put_frame(buf, 0x02, "b", 1);
    CHECK(nbl_ws_next(&st, buf, n, &ev) < 0);

    /* a fragmented message over capacity is rejected from the header of the fragment that
     * would overflow, before its payload has arrived */
    nbl_ws_init(&st, msg, 8);
    n = put_frame(buf, 0x02, "123456", 6);
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_NEED_MORE);
    n = put_frame(buf, 0x80, "789", 3);
    CHECK(nbl_ws_next(&st, buf, 2, &ev) < 0);
    CHECK(nbl_ws_next(&st, buf, n, &ev) < 0);
    /* exactly the capacity is fine */
    nbl_ws_init(&st, msg, 8);
    n = put_frame(buf, 0x02, "123456", 6);
    n += put_frame(buf + n, 0x80, "78", 2);
    CHECK(drain(&st, buf, n, &ev) == 0 && ev.type == NBL_WS_DATA && ev.len == 8 && !memcmp(ev.data, "12345678", 8));
    /* a single frame over capacity */
    nbl_ws_init(&st, msg, 4);
    n = put_frame(buf, 0x82, "12345", 5);
    CHECK(nbl_ws_next(&st, buf, 2, &ev) < 0);

    /* control frames may be interleaved with fragments: PING between two fragments */
    nbl_ws_init(&st, msg, sizeof(msg));
    n = put_frame(buf, 0x02, "abc", 3);
    size_t p1 = n;
    n += put_frame(buf + n, 0x89, "hi", 2);
    size_t p2 = n;
    n += put_frame(buf + n, 0x80, "def", 3);
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)p1 && ev.type == NBL_WS_NEED_MORE);
    CHECK(nbl_ws_next(&st, buf + p1, n - p1, &ev) == (int)(p2 - p1) && ev.type == NBL_WS_PING &&
          ev.len == 2 && !memcmp(ev.data, "hi", 2));
    CHECK(nbl_ws_next(&st, buf + p2, n - p2, &ev) == (int)(n - p2) && ev.type == NBL_WS_DATA &&
          ev.len == 6 && !memcmp(ev.data, "abcdef", 6));
    /* the same through nbl_ws_poll(): the PING is reported, the fragment skipped silently */
    nbl_ws_init(&st, msg, sizeof(msg));
    size_t used = 0;
    CHECK(nbl_ws_poll(&st, buf, n, &used, &ev) == 1 && used == p2 && ev.type == NBL_WS_PING);
    CHECK(nbl_ws_poll(&st, buf + used, n - used, &used, &ev) == 1 && used == n - p2 && ev.type == NBL_WS_DATA &&
          ev.len == 6);

    /* a new connection starts from a clean state (nbl_ws_init), even mid-fragment */
    nbl_ws_init(&st, msg, sizeof(msg));
    n = put_frame(buf, 0x02, "abc", 3);
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_NEED_MORE);
    n = put_frame(buf, 0x82, "\x01\x07u", 3);
    nbl_ws_init(&st, msg, sizeof(msg));
    CHECK(nbl_ws_next(&st, buf, n, &ev) == (int)n && ev.type == NBL_WS_DATA && ev.len == 3);
}

static void test_strict(void)
{
    nbl_ws_t st;
    nbl_ws_event_t ev;
    nbl_ws_init(&st, msg, sizeof(msg));

    /* RSV1, RSV2, RSV3 */
    uint8_t rsv[3][3] = {{0xC2, 1, 'x'}, {0xA2, 1, 'x'}, {0x92, 1, 'x'}};
    for (int i = 0; i < 3; i++) {
        CHECK(nbl_ws_next(&st, rsv[i], 3, &ev) < 0);
    }
    uint8_t rsv_ping[2] = {0xC9, 0};
    CHECK(nbl_ws_next(&st, rsv_ping, 2, &ev) < 0);
    /* masked frames from the server (data and control) */
    uint8_t masked[7] = {0x82, 0x81, 1, 2, 3, 4, 'x'};
    CHECK(nbl_ws_next(&st, masked, sizeof(masked), &ev) < 0);
    uint8_t masked_ping[6] = {0x89, 0x80, 1, 2, 3, 4};
    CHECK(nbl_ws_next(&st, masked_ping, sizeof(masked_ping), &ev) < 0);
    /* control frames above 125 bytes (16-bit length) and with FIN=0 */
    uint8_t ctl_big[4 + 126] = {0x89, 126, 0, 126};
    CHECK(nbl_ws_next(&st, ctl_big, sizeof(ctl_big), &ev) < 0);
    CHECK(nbl_ws_next(&st, ctl_big, 2, &ev) < 0);
    uint8_t ctl_big64[10] = {0x8A, 127, 0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(nbl_ws_next(&st, ctl_big64, sizeof(ctl_big64), &ev) < 0);
    uint8_t ping_nofin[2] = {0x09, 0};
    CHECK(nbl_ws_next(&st, ping_nofin, 2, &ev) < 0);
    uint8_t close_nofin[4] = {0x08, 2, 0x03, 0xe8};
    CHECK(nbl_ws_next(&st, close_nofin, sizeof(close_nofin), &ev) < 0);
    /* a 125-byte PING is the largest allowed control frame */
    uint8_t ping125[2 + 125] = {0x89, 125};
    CHECK(nbl_ws_next(&st, ping125, sizeof(ping125), &ev) == (int)sizeof(ping125) && ev.type == NBL_WS_PING &&
          ev.len == 125);
    /* close: 1-byte payload invalid; empty or status code fine */
    uint8_t close1[3] = {0x88, 1, 0x03};
    CHECK(nbl_ws_next(&st, close1, sizeof(close1), &ev) < 0);
    uint8_t close0[2] = {0x88, 0};
    CHECK(nbl_ws_next(&st, close0, 2, &ev) == 2 && ev.type == NBL_WS_CLOSE && ev.len == 0);
    uint8_t close2[4] = {0x88, 2, 0x03, 0xe8};
    CHECK(nbl_ws_next(&st, close2, 4, &ev) == 4 && ev.type == NBL_WS_CLOSE && ev.len == 2 && ev.data[0] == 0x03 &&
          ev.data[1] == 0xe8);
    /* text frames (the relay only uses binary messages) and every reserved opcode */
    uint8_t text[3] = {0x81, 1, 'a'};
    CHECK(nbl_ws_next(&st, text, 3, &ev) < 0);
    for (uint8_t op = 0x3; op <= 0xF; op++) {
        if (op == 0x8 || op == 0x9 || op == 0xA) {
            continue;
        }
        uint8_t f[2] = {(uint8_t)(0x80 | op), 0};
        CHECK(nbl_ws_next(&st, f, 2, &ev) < 0);
    }
    /* none of the rejected frames changed the state: a normal message still parses */
    uint8_t ok[4] = {0x82, 2, 1, 5};
    CHECK(nbl_ws_next(&st, ok, 4, &ev) == 4 && ev.type == NBL_WS_DATA && ev.len == 2);
}

static void test_pong_burst(void)
{
    nbl_ws_t st;
    nbl_ws_event_t ev;
    size_t used = 0;

    /* 300 empty PONG frames followed by a data frame: one call, no recursion */
    size_t n = 0;
    for (int i = 0; i < 300; i++) {
        n += put_frame(buf + n, 0x8A, NULL, 0);
    }
    size_t pongs = n;
    n += put_frame(buf + n, 0x82, "\x01\x05", 2);
    nbl_ws_init(&st, msg, sizeof(msg));
    CHECK(nbl_ws_poll(&st, buf, n, &used, &ev) == 1 && used == n && ev.type == NBL_WS_DATA && ev.len == 2);
    /* only PONGs: everything consumed, nothing to report */
    CHECK(nbl_ws_poll(&st, buf, pongs, &used, &ev) == 0 && used == pongs);
    /* a whole receive buffer of empty PONGs (4442 frames) */
    for (n = 0; n + 2 <= ACC_CAP; n += 2) {
        buf[n] = 0x8A;
        buf[n + 1] = 0;
    }
    CHECK(nbl_ws_poll(&st, buf, n, &used, &ev) == 0 && used == n);
    /* PONGs, then a truncated frame: the PONGs are consumed, the rest waits */
    CHECK(nbl_ws_poll(&st, buf, 7, &used, &ev) == 0 && used == 6);
    /* PONGs, then a protocol error: used counts the good frames */
    buf[6] = 0x81;
    buf[7] = 0;
    CHECK(nbl_ws_poll(&st, buf, 8, &used, &ev) < 0 && used == 6);
    /* PONG with payload is skipped as well */
    n = put_frame(buf, 0x8A, "pong", 4);
    n += put_frame(buf + n, 0x89, "ping", 4);
    CHECK(nbl_ws_poll(&st, buf, n, &used, &ev) == 1 && used == n && ev.type == NBL_WS_PING && ev.len == 4 &&
          !memcmp(ev.data, "ping", 4));
}

static void test_build(void)
{
    static uint8_t out[14 + NBL_R_MAX_MSG];
    static uint8_t pay[NBL_R_MAX_MSG];
    const uint8_t mask[4] = {0xA1, 0xB2, 0xC3, 0xD4};
    for (size_t i = 0; i < sizeof(pay); i++) {
        pay[i] = (uint8_t)(i * 7);
    }
    /* empty PONG: FIN + opcode, MASK bit, then the mask */
    CHECK(nbl_ws_build(NBL_WS_OP_PONG, NULL, 0, mask, out, sizeof(out)) == 6);
    CHECK(out[0] == 0x8A && out[1] == 0x80 && !memcmp(out + 2, mask, 4));
    /* 125 (7-bit), 126 and NBL_R_MAX_MSG (16-bit): unmask and parse as a server frame */
    size_t lens[3] = {125, 126, NBL_R_MAX_MSG};
    for (int k = 0; k < 3; k++) {
        size_t L = lens[k];
        int n = nbl_ws_build(NBL_WS_OP_BINARY, pay, L, mask, out, sizeof(out));
        size_t hl = L < 126 ? 2 : 4;
        CHECK(n == (int)(hl + 4 + L));
        CHECK(out[0] == 0x82 && (out[1] & 0x80));
        /* turn it into what a server would send: clear MASK, drop the key, unmask */
        static uint8_t srv[14 + NBL_R_MAX_MSG];
        memcpy(srv, out, hl);
        srv[1] &= 0x7f;
        for (size_t i = 0; i < L; i++) {
            srv[hl + i] = out[hl + 4 + i] ^ mask[i & 3];
        }
        nbl_ws_t st;
        nbl_ws_event_t ev;
        nbl_ws_init(&st, msg, sizeof(msg));
        CHECK(nbl_ws_next(&st, srv, hl + L, &ev) == (int)(hl + L) && ev.type == NBL_WS_DATA && ev.len == L &&
              !memcmp(ev.data, pay, L));
    }
    /* the TX buffer in nbl_relay.c (14 + NBL_R_MAX_MSG) holds the largest message; one byte
     * less is too small */
    CHECK(nbl_ws_build(NBL_WS_OP_BINARY, pay, NBL_R_MAX_MSG, mask, out, 8 + NBL_R_MAX_MSG) == 8 + NBL_R_MAX_MSG);
    CHECK(nbl_ws_build(NBL_WS_OP_BINARY, pay, NBL_R_MAX_MSG, mask, out, 7 + NBL_R_MAX_MSG) < 0);
}

#define ACCEPT "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" /* RFC 6455 1.3 example */

static int hs(const char *resp)
{
    return nbl_ws_handshake_response(resp, strlen(resp), ACCEPT);
}

static void test_handshake(void)
{
    const char *ok = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: " ACCEPT "\r\n\r\n";
    size_t len = strlen(ok);
    CHECK(hs(ok) == (int)len);
    /* every prefix is incomplete; nothing reads past len (ASan) */
    int prefix_ok = 1;
    for (size_t i = 0; i < len; i++) {
        char *p = malloc(i ? i : 1);
        memcpy(p, ok, i);
        if (nbl_ws_handshake_response(p, i, ACCEPT) != 0) {
            prefix_ok = 0;
        }
        free(p);
    }
    CHECK(prefix_ok);
    /* bytes after the header block (a first frame) are not part of it */
    char with_frame[256];
    snprintf(with_frame, sizeof(with_frame), "%s\x82\x02\x01\x05", ok);
    CHECK(hs(with_frame) == (int)len);

    /* status */
    CHECK(hs("HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 1010 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.0 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") > 0);
    CHECK(hs("\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\n\r\n") < 0);
    /* names and tokens are case-insensitive, lists and optional whitespace are allowed */
    CHECK(hs("HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\n"
             "sec-websocket-accept:\t" ACCEPT " \r\n\r\n") > 0);
    /* Upgrade and Connection must be present and carry the token itself */
    CHECK(hs("HTTP/1.1 101 X\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " ACCEPT "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocketx\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: upgraded\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nX-Connection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\n\r\n") < 0);
    /* Sec-WebSocket-Accept only counts in its own header line and must match exactly */
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Note: " ACCEPT "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Note: " ACCEPT
             "\r\nSec-WebSocket-Accept: wrong\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "x\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x" ACCEPT
             "\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
             "S3PPLMBITXAQ9KYGZZHZRBK+XOO=\r\n\r\n") < 0);
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept-X: " ACCEPT
             "\r\n\r\n") < 0);
    /* a malformed header line */
    CHECK(hs("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ACCEPT
             "\r\nno colon here\r\n\r\n") < 0);
}

static void test_relaymsg(void)
{
    nbl_relay_msg_t m;
    static uint8_t b[2 + NBL_RELAY_ID_LEN + NBL_R_MAX_TRANSPORT_PAYLOAD + 1];
    memset(b, 0, sizeof(b));
    b[0] = NBL_R_PROTO;

    /* unknown and client-only types, among them AUTH sent by the server */
    int types_ok = 1;
    for (int t = 0; t < 256; t++) {
        b[1] = (uint8_t)t;
        int known = t == NBL_R_TRANSPORT || t == NBL_R_CLOSE || t == NBL_R_HEALTH || t == NBL_R_AUTH_RESP;
        if (!known && nbl_relay_parse(b, 2 + NBL_RELAY_ID_LEN, &m) == 0) {
            types_ok = 0;
        }
    }
    CHECK(types_ok);
    b[1] = NBL_R_AUTH;
    CHECK(nbl_relay_parse(b, sizeof(b), &m) < 0);

    /* transport: exactly the minimum size (empty payload), one byte less, the largest
     * accepted payload and one byte more */
    b[1] = NBL_R_TRANSPORT;
    memset(b + 2, 'I', NBL_RELAY_ID_LEN);
    CHECK(nbl_relay_parse(b, 2 + NBL_RELAY_ID_LEN, &m) == 0 && m.type == NBL_R_TRANSPORT && m.payload_len == 0 &&
          m.id == b + 2 && m.payload == b + 2 + NBL_RELAY_ID_LEN);
    CHECK(nbl_relay_parse(b, 2 + NBL_RELAY_ID_LEN - 1, &m) < 0);
    CHECK(nbl_relay_parse(b, 2 + NBL_RELAY_ID_LEN + NBL_R_MAX_TRANSPORT_PAYLOAD, &m) == 0 &&
          m.payload_len == NBL_R_MAX_TRANSPORT_PAYLOAD);
    CHECK(nbl_relay_parse(b, sizeof(b), &m) < 0);

    /* auth response needs an instance URL (upstream UnmarshalAuthResponse) */
    uint8_t ar[3] = {NBL_R_PROTO, NBL_R_AUTH_RESP, 'x'};
    CHECK(nbl_relay_parse(ar, 2, &m) < 0);
    CHECK(nbl_relay_parse(ar, 3, &m) == 0 && m.payload_len == 1 && m.payload[0] == 'x');
    /* health check and close carry nothing */
    uint8_t hc[2] = {NBL_R_PROTO, NBL_R_HEALTH}, cl[2] = {NBL_R_PROTO, NBL_R_CLOSE};
    CHECK(nbl_relay_parse(hc, 2, &m) == 0 && m.type == NBL_R_HEALTH);
    CHECK(nbl_relay_parse(cl, 2, &m) == 0 && m.type == NBL_R_CLOSE);
    /* wrong version, too short, NULL */
    uint8_t v2[2] = {2, NBL_R_HEALTH};
    CHECK(nbl_relay_parse(v2, 2, &m) < 0);
    CHECK(nbl_relay_parse(hc, 1, &m) < 0);
    CHECK(nbl_relay_parse(NULL, 0, &m) < 0);
}

static int url(const char *u, const char *want_host, int want_port)
{
    char host[16];
    uint16_t port = 0;
    memset(host, '#', sizeof(host));
    int r = nbl_relay_parse_url(u, host, sizeof(host), &port);
    if (want_host == NULL) {
        return r < 0;
    }
    return r == 0 && strcmp(host, want_host) == 0 && port == want_port;
}

static void test_url(void)
{
    CHECK(url("rels://relay.example", "relay.example", 443));
    CHECK(url("rels://relay.example:8443", "relay.example", 8443));
    CHECK(url("rels://relay.example:443/relay", "relay.example", 443));
    CHECK(url("rels://relay.example/", "relay.example", 443));
    CHECK(url("rels://10.0.0.1:1", "10.0.0.1", 1));
    CHECK(url("rels://a_b-c:65535", "a_b-c", 65535));
    CHECK(url("rels://h:00080", "h", 80));
    /* port range and syntax */
    CHECK(url("rels://h:0", NULL, 0));
    CHECK(url("rels://h:65536", NULL, 0));
    CHECK(url("rels://h:99999", NULL, 0));
    CHECK(url("rels://h:123456", NULL, 0));
    CHECK(url("rels://h:", NULL, 0));
    CHECK(url("rels://h:44a", NULL, 0));
    CHECK(url("rels://h:-1", NULL, 0));
    CHECK(url("rels://h:443:1", NULL, 0));
    /* schemes: rel:// (plain WebSocket) is not implemented */
    CHECK(url("rel://h", NULL, 0));
    CHECK(url("https://h", NULL, 0));
    CHECK(url("RELS://h", NULL, 0));
    CHECK(url("rels:/h", NULL, 0));
    CHECK(url("", NULL, 0));
    /* host: empty, IPv6 literal, user info, junk, too long for the buffer */
    CHECK(url("rels://", NULL, 0));
    CHECK(url("rels://:443", NULL, 0));
    CHECK(url("rels://[2001:db8::1]:443", NULL, 0));
    CHECK(url("rels://[2001:db8::1]", NULL, 0));
    CHECK(url("rels://user@h", NULL, 0));
    CHECK(url("rels://h?x=1", NULL, 0));
    CHECK(url("rels://h r", NULL, 0));
    CHECK(url("rels://h\r\nX: y", NULL, 0));
    CHECK(url("rels://123456789012345", "123456789012345", 443)); /* 15 chars + NUL = 16 */
    CHECK(url("rels://1234567890123456", NULL, 0));
}

int main(void)
{
    test_lengths();
    test_fragments();
    test_strict();
    test_pong_burst();
    test_build();
    test_handshake();
    test_relaymsg();
    test_url();
    if (fails) {
        printf("test_relay: %d of %d checks FAILED\n", fails, checks);
        return 1;
    }
    printf("test_relay: all %d checks passed\n", checks);
    return 0;
}
