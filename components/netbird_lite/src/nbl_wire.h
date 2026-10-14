// SPDX-License-Identifier: MIT
// Hand-written encoding of the two "EncryptedMessage" envelopes (management: wgPubKey=1 body=2 version=3,
// signal: key=2 remoteKey=3 body=4). The envelope is trivial and the body is large, so nanopb would only add a detour.
// The decoder reads untrusted input (signal messages are relayed from any peer): every length is
// checked against the remaining input and varints are limited to 10 bytes.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline size_t nbl_put_varint(uint8_t *o, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) {
        o[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    o[n++] = (uint8_t)v;
    return n;
}

/** Writes a length-delimited field. Returns the new length. No bounds check: the caller sizes the buffer. */
static inline size_t nbl_put_bytes(uint8_t *o, size_t pos, int field, const void *d, size_t len)
{
    o[pos++] = (uint8_t)((field << 3) | 2);
    pos += nbl_put_varint(o + pos, len);
    memcpy(o + pos, d, len);
    return pos + len;
}

static inline size_t nbl_put_int(uint8_t *o, size_t pos, int field, uint64_t v)
{
    o[pos++] = (uint8_t)((field << 3) | 0);
    return pos + nbl_put_varint(o + pos, v);
}

/** Reads a varint from b[0..len). Returns the number of bytes used (1..10), or 0 if the input ends
 *  inside the varint or the value does not fit into 64 bits (more than 10 bytes, or a 10th byte
 *  above 1). */
static inline size_t nbl_get_varint(const uint8_t *b, size_t len, uint64_t *v)
{
    uint64_t r = 0;
    for (size_t i = 0; i < len && i < 10; i++) {
        uint8_t c = b[i];
        if (i == 9 && c > 1) {
            return 0;
        }
        r |= (uint64_t)(c & 0x7f) << (7 * i);
        if (!(c & 0x80)) {
            *v = r;
            return i + 1;
        }
    }
    return 0;
}

/** Finds the first length-delimited field with the given number (1..2^29-1). Returns 0 if found
 *  (*d points into b, *dl bytes), -1 if not found or the input is malformed: truncated, a length
 *  beyond the end of the input, field number 0, or wire type 3/4 (groups), 6 or 7. */
static inline int nbl_get_bytes(const uint8_t *b, size_t len, int field, const uint8_t **d, size_t *dl)
{
    size_t p = 0;
    while (p < len) {
        uint64_t tag, v;
        size_t n = nbl_get_varint(b + p, len - p, &tag);
        if (n == 0 || (tag >> 3) == 0) {
            return -1;
        }
        p += n;
        switch (tag & 7) {
        case 0: /* varint */
            n = nbl_get_varint(b + p, len - p, &v);
            if (n == 0) {
                return -1;
            }
            p += n;
            break;
        case 1: /* 64-bit */
            if (len - p < 8) {
                return -1;
            }
            p += 8;
            break;
        case 5: /* 32-bit */
            if (len - p < 4) {
                return -1;
            }
            p += 4;
            break;
        case 2: /* length-delimited */
            n = nbl_get_varint(b + p, len - p, &v);
            if (n == 0) {
                return -1;
            }
            p += n;
            if (v > len - p) { /* never p + v: a 64-bit length would wrap */
                return -1;
            }
            if ((tag >> 3) == (uint64_t)field) {
                *d = b + p;
                *dl = (size_t)v;
                return 0;
            }
            p += (size_t)v;
            break;
        default: /* 3/4: groups (deprecated, never used by NetBird), 6/7: invalid */
            return -1;
        }
    }
    return -1;
}
