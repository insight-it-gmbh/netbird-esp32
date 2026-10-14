// SPDX-License-Identifier: MIT
// gRPC message framing (1-byte flag + 4-byte big-endian length) as a pure state machine.
// Messages are delivered via callback; the buffer belongs to the state machine and is
// only valid for the duration of the callback.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*nbl_grpc_msg_fn)(void *ctx, const uint8_t *msg, size_t len);

typedef struct {
    uint8_t hdr[5];
    size_t hdr_len;
    uint8_t *msg; /* allocated internally (exact length) */
    size_t msg_len, msg_expect, msg_cap;
    bool in_msg;
} nbl_grpc_rx_t;

void nbl_grpc_rx_init(nbl_grpc_rx_t *st, size_t msg_cap);
void nbl_grpc_rx_free(nbl_grpc_rx_t *st);

/** Consumes d[0..n) completely. 0 = ok, <0 = error (drop the stream afterwards):
 *  -1 compressed/invalid flag, -2 message larger than msg_cap, -3 out of memory. */
int nbl_grpc_rx_feed(nbl_grpc_rx_t *st, nbl_grpc_msg_fn cb, void *ctx, const uint8_t *d, size_t n);

/** Frames one message. Returns the total length (5 + len) or -1 if cap is too small. */
int nbl_grpc_frame(uint8_t *out, size_t cap, const uint8_t *msg, size_t len);

#ifdef __cplusplus
}
#endif
