// SPDX-License-Identifier: MIT
#include "nbl_grpc.h"

#include <string.h>

void nbl_grpc_rx_init(nbl_grpc_rx_t *st, size_t msg_cap)
{
    memset(st, 0, sizeof(*st));
    st->msg_cap = msg_cap;
}

void nbl_grpc_rx_free(nbl_grpc_rx_t *st)
{
    free(st->msg);
    st->msg = NULL;
    st->msg_len = st->msg_expect = st->hdr_len = 0;
    st->in_msg = false;
}

int nbl_grpc_rx_feed(nbl_grpc_rx_t *st, nbl_grpc_msg_fn cb, void *ctx, const uint8_t *d, size_t n)
{
    while (n) {
        if (!st->in_msg) {
            size_t take = 5 - st->hdr_len;
            if (take > n) {
                take = n;
            }
            memcpy(st->hdr + st->hdr_len, d, take);
            st->hdr_len += take;
            d += take;
            n -= take;
            if (st->hdr_len < 5) {
                return 0;
            }
            if (st->hdr[0] != 0) {
                return -1; /* compressed (or invalid flag): not supported */
            }
            size_t len = ((size_t)st->hdr[1] << 24) | ((size_t)st->hdr[2] << 16) |
                         ((size_t)st->hdr[3] << 8) | st->hdr[4];
            if (len > st->msg_cap) {
                return -2;
            }
            free(st->msg);
            st->msg = malloc(len ? len : 1);
            if (!st->msg) {
                return -3;
            }
            st->msg_expect = len;
            st->msg_len = 0;
            st->in_msg = true;
        }
        size_t take = st->msg_expect - st->msg_len;
        if (take > n) {
            take = n;
        }
        if (take) {
            memcpy(st->msg + st->msg_len, d, take);
            st->msg_len += take;
            d += take;
            n -= take;
        }
        if (st->msg_len == st->msg_expect) {
            uint8_t *done = st->msg;
            size_t done_len = st->msg_len;
            st->in_msg = false;
            st->hdr_len = 0;
            st->msg = NULL; /* next message gets a new buffer; this one stays valid during cb */
            if (cb) {
                cb(ctx, done, done_len);
            }
            free(done);
        }
    }
    return 0;
}

int nbl_grpc_frame(uint8_t *out, size_t cap, const uint8_t *msg, size_t len)
{
    if (cap < 5 + len) {
        return -1;
    }
    out[0] = 0;
    out[1] = (uint8_t)(len >> 24);
    out[2] = (uint8_t)(len >> 16);
    out[3] = (uint8_t)(len >> 8);
    out[4] = (uint8_t)len;
    if (len) {
        memcpy(out + 5, msg, len);
    }
    return (int)(5 + len);
}
