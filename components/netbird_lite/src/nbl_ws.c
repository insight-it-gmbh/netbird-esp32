// SPDX-License-Identifier: Apache-2.0
#include "nbl_ws.h"

#include <string.h>

void nbl_ws_init(nbl_ws_t *st, uint8_t *msg_buf, size_t msg_cap)
{
    st->msg = msg_buf;
    st->msg_cap = msg_cap;
    st->msg_len = 0;
    st->in_msg = false;
}

int nbl_ws_next(nbl_ws_t *st, const uint8_t *acc, size_t acc_len, nbl_ws_event_t *ev)
{
    if (acc_len < 2) {
        return 0;
    }
    uint8_t b0 = acc[0], b1 = acc[1];
    bool fin = b0 & 0x80;
    uint8_t op = b0 & 0x0f;
    size_t pl = b1 & 0x7f;
    size_t hl = 2;
    /* No extension was negotiated, so RSV1-3 must be 0, and a server never masks (RFC 6455
     * 5.1, 5.2). */
    if ((b0 & 0x70) || (b1 & 0x80)) {
        return -1;
    }
    if (op & 0x8) {
        /* Control frame: never fragmented, at most 125 bytes, a close payload starts with a
         * 2-byte status code (RFC 6455 5.5). */
        if (op > NBL_WS_OP_PONG || !fin || pl > 125 || (op == NBL_WS_OP_CLOSE && pl == 1)) {
            return -1;
        }
    } else if (op != 0x0 && op != NBL_WS_OP_BINARY) {
        return -1; /* text (the relay only sends binary messages) or reserved opcode */
    } else if ((op == 0x0) != st->in_msg) {
        return -1; /* continuation without a start frame, or a new message inside another */
    }
    if (pl == 126) {
        if (acc_len < 4) {
            return 0;
        }
        pl = ((size_t)acc[2] << 8) | acc[3];
        hl = 4;
        if (pl < 126) {
            return -1; /* not the minimal length encoding */
        }
    } else if (pl == 127) {
        /* A 64-bit length is only minimal above 0xffff, and the relay never sends frames
         * above 64 KiB. */
        return -1;
    }
    if (!(op & 0x8) && pl > st->msg_cap - (op == 0x0 ? st->msg_len : 0)) {
        return -1; /* the (reassembled) message would not fit */
    }
    if (acc_len - hl < pl) {
        return 0;
    }
    const uint8_t *pay = acc + hl;
    size_t total = hl + pl;

    if (op & 0x8) {
        ev->type = op == NBL_WS_OP_CLOSE ? NBL_WS_CLOSE : op == NBL_WS_OP_PING ? NBL_WS_PING : NBL_WS_PONG;
        ev->data = pay;
        ev->len = pl;
        return (int)total;
    }
    if (op == NBL_WS_OP_BINARY) {
        st->in_msg = true;
        st->msg_len = 0;
    }
    memcpy(st->msg + st->msg_len, pay, pl);
    st->msg_len += pl;
    if (!fin) {
        ev->type = NBL_WS_NEED_MORE; /* frame consumed, message still incomplete */
        ev->data = NULL;
        ev->len = 0;
        return (int)total;
    }
    st->in_msg = false;
    ev->type = NBL_WS_DATA;
    ev->data = st->msg;
    ev->len = st->msg_len;
    return (int)total;
}

int nbl_ws_poll(nbl_ws_t *st, const uint8_t *acc, size_t acc_len, size_t *used, nbl_ws_event_t *ev)
{
    /* A loop, not recursion: a burst of tiny frames must not grow the stack. */
    size_t off = 0;
    for (;;) {
        int n = nbl_ws_next(st, acc + off, acc_len - off, ev);
        if (n <= 0) {
            *used = off;
            return n < 0 ? -1 : 0;
        }
        off += (size_t)n;
        if (ev->type != NBL_WS_PONG && ev->type != NBL_WS_NEED_MORE) {
            *used = off;
            return 1;
        }
    }
}

int nbl_ws_build(uint8_t opcode, const uint8_t *payload, size_t len, const uint8_t mask[4],
                 uint8_t *out, size_t out_cap)
{
    size_t hl = 2;
    if (len >= 126) {
        hl += len <= 0xffff ? 2 : 8;
    }
    if (hl + 4 + len > out_cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = 0x80 | opcode;
    if (len < 126) {
        out[o++] = 0x80 | (uint8_t)len;
    } else if (len <= 0xffff) {
        out[o++] = 0x80 | 126;
        out[o++] = (uint8_t)(len >> 8);
        out[o++] = (uint8_t)len;
    } else {
        out[o++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) {
            out[o++] = (uint8_t)((uint64_t)len >> (8 * i));
        }
    }
    uint8_t m[4] = {1, 2, 3, 4};
    if (mask) {
        memcpy(m, mask, 4);
    }
    memcpy(out + o, m, 4);
    o += 4;
    for (size_t i = 0; i < len; i++) {
        out[o + i] = payload[i] ^ m[i & 3];
    }
    return (int)(o + len);
}

/* ---------------- Opening handshake response ---------------- */

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
}

/* s[0..n) equals the NUL-terminated lowercase word w, ASCII case-insensitive */
static bool ieq(const char *s, size_t n, const char *w)
{
    size_t i = 0;
    while (i < n && w[i] && lower(s[i]) == w[i]) {
        i++;
    }
    return i == n && !w[i];
}

static bool is_ows(char c)
{
    return c == ' ' || c == '\t';
}

/* The comma-separated list v[0..n) contains the token tok (lowercase), case-insensitive */
static bool has_token(const char *v, size_t n, const char *tok)
{
    for (size_t s = 0; s <= n;) {
        size_t e = s;
        while (e < n && v[e] != ',') {
            e++;
        }
        size_t a = s, b = e;
        while (a < b && is_ows(v[a])) {
            a++;
        }
        while (b > a && is_ows(v[b - 1])) {
            b--;
        }
        if (ieq(v + a, b - a, tok)) {
            return true;
        }
        s = e + 1;
    }
    return false;
}

/* Offset of the next "\r\n" at or after i, or len if there is none */
static size_t find_crlf(const char *buf, size_t len, size_t i)
{
    while (i + 1 < len && !(buf[i] == '\r' && buf[i + 1] == '\n')) {
        i++;
    }
    return i + 1 < len ? i : len;
}

int nbl_ws_handshake_response(const char *buf, size_t len, const char *accept)
{
    /* The header block ends with the first empty line. */
    size_t end = 0;
    for (size_t i = find_crlf(buf, len, 0); i < len; i = find_crlf(buf, len, i + 2)) {
        if (i + 4 <= len && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = i + 4;
            break;
        }
    }
    if (!end) {
        return 0;
    }
    /* Status line "HTTP/1.1 101 <reason>" */
    if (end < 13 || memcmp(buf, "HTTP/1.1 101", 12) != 0 || (buf[12] != ' ' && buf[12] != '\r')) {
        return -1;
    }
    bool upgrade = false, connection = false, accepted = false;
    size_t acc_len = strlen(accept);
    /* One header line per pass; the block ends with "\r\n\r\n", so every line before the
     * final empty one (at end - 2) has its CRLF inside the block. */
    for (size_t i = find_crlf(buf, end, 0) + 2; i + 2 < end;) {
        size_t eol = find_crlf(buf, end, i);
        const char *line = buf + i;
        const char *colon = memchr(line, ':', eol - i);
        if (!colon) {
            return -1;
        }
        size_t name_len = (size_t)(colon - line);
        size_t a = name_len + 1, b = eol - i;
        while (a < b && is_ows(line[a])) {
            a++;
        }
        while (b > a && is_ows(line[b - 1])) {
            b--;
        }
        if (ieq(line, name_len, "upgrade")) {
            upgrade = upgrade || has_token(line + a, b - a, "websocket");
        } else if (ieq(line, name_len, "connection")) {
            connection = connection || has_token(line + a, b - a, "upgrade");
        } else if (ieq(line, name_len, "sec-websocket-accept")) {
            if (b - a != acc_len || memcmp(line + a, accept, acc_len) != 0) {
                return -1;
            }
            accepted = true;
        }
        i = eol + 2;
    }
    return upgrade && connection && accepted ? (int)end : -1;
}
