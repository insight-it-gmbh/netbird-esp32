// libFuzzer target for the pure parts of the relay transport: the WebSocket frame stream
// (parsed as a whole and in chunks, which must give the same events), the handshake response
// check, the relay message parser and the relay URL parser. Violated invariants trap.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nbl_relaymsg.h"
#include "nbl_ws.h"

#define MSG_CAP (NBL_R_MAX_MSG + 32) /* as in nbl_relay.c */
#define MAX_EV 512
#define ACCEPT "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

static uint8_t msg_buf[MSG_CAP];

struct evrec {
    int type;
    size_t len;
    uint32_t sum;
};

struct run {
    struct evrec ev[MAX_EV];
    int n_ev;
    int err;
    size_t consumed;
};

static struct run whole, chunked;

#define CHECK(c) do { if (!(c)) __builtin_trap(); } while (0)

static uint32_t sum(const uint8_t *d, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h = (h ^ d[i]) * 16777619u;
    }
    return h;
}

/* Delivers d[0..n) in chunks of step bytes (0 = everything at once), like fill() does,
 * and records every event nbl_ws_poll() reports. */
static void ws_run(const uint8_t *d, size_t n, size_t step, struct run *out)
{
    nbl_ws_t st;
    nbl_ws_init(&st, msg_buf, sizeof(msg_buf));
    size_t off = 0, avail = step ? (step < n ? step : n) : n;
    out->n_ev = 0;
    out->err = 0;
    for (;;) {
        nbl_ws_event_t ev;
        size_t used = (size_t)-1;
        int r = nbl_ws_poll(&st, d + off, avail - off, &used, &ev);
        CHECK(used <= avail - off);
        off += used;
        if (r < 0) {
            out->err = 1;
            break;
        }
        if (r == 1) {
            CHECK(used >= 2);
            CHECK(ev.type == NBL_WS_DATA || ev.type == NBL_WS_PING || ev.type == NBL_WS_CLOSE);
            CHECK(ev.type == NBL_WS_DATA ? ev.len <= MSG_CAP : ev.len <= 125);
            CHECK(ev.type != NBL_WS_CLOSE || ev.len != 1);
            if (out->n_ev < MAX_EV) {
                out->ev[out->n_ev] = (struct evrec){ev.type, ev.len, sum(ev.data, ev.len)};
            }
            out->n_ev++;
            continue;
        }
        if (avail == n) {
            break;
        }
        avail = avail + step < n ? avail + step : n;
    }
    out->consumed = off;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 16384) {
        return 0;
    }

    /* 1. WebSocket stream: whole vs. chunked delivery must agree */
    ws_run(data, size, 0, &whole);
    ws_run(data, size, 1 + data[0] % 13, &chunked);
    CHECK(whole.err == chunked.err && whole.n_ev == chunked.n_ev && whole.consumed == chunked.consumed);
    for (int i = 0; i < whole.n_ev && i < MAX_EV; i++) {
        CHECK(whole.ev[i].type == chunked.ev[i].type && whole.ev[i].len == chunked.ev[i].len &&
              whole.ev[i].sum == chunked.ev[i].sum);
    }

    /* 2. handshake response: a result > 0 ends with the first empty line */
    int h = nbl_ws_handshake_response((const char *)data, size, ACCEPT);
    CHECK(h <= (int)size);
    if (h > 0) {
        CHECK(h >= 16 && !memcmp(data + h - 4, "\r\n\r\n", 4) && !memcmp(data, "HTTP/1.1 101", 12));
        CHECK(nbl_ws_handshake_response((const char *)data, (size_t)h - 1, ACCEPT) == 0);
    }

    /* 3. relay message */
    nbl_relay_msg_t m;
    if (nbl_relay_parse(data, size, &m) == 0) {
        CHECK(m.type == NBL_R_TRANSPORT || m.type == NBL_R_CLOSE || m.type == NBL_R_HEALTH ||
              m.type == NBL_R_AUTH_RESP);
        if (m.payload) {
            CHECK(m.payload >= data && m.payload + m.payload_len == data + size);
        }
        CHECK(m.type != NBL_R_TRANSPORT || (m.id == data + 2 && m.payload_len <= NBL_R_MAX_TRANSPORT_PAYLOAD));
        CHECK(m.type != NBL_R_AUTH_RESP || m.payload_len >= 1);
    }

    /* 4. relay URL (NUL-terminated copy) */
    char url[256], host[64];
    size_t ul = size < sizeof(url) - 1 ? size : sizeof(url) - 1;
    memcpy(url, data, ul);
    url[ul] = 0;
    uint16_t port = 0;
    if (nbl_relay_parse_url(url, host, sizeof(host), &port) == 0) {
        size_t hl = strlen(host);
        CHECK(hl > 0 && hl < sizeof(host) && port >= 1 && !strncmp(url, "rels://", 7) &&
              !strncmp(url + 7, host, hl));
        for (size_t i = 0; i < hl; i++) {
            char c = host[i];
            CHECK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                  c == '.' || c == '_');
        }
    }
    return 0;
}
