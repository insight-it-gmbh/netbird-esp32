// SPDX-License-Identifier: MIT
// Minimal gRPC client over HTTP/2 + TLS (esp-tls). Implemented by nbl_h2_lite.c (own HTTP/2
// stack, default) or nbl_h2.c (nghttp2, CONFIG_NBL_H2_NGHTTP2).
// One connection, several streams (management and signal often share the same host).
// Everything runs in the context of ONE task: nbl_h2_run() drives I/O and the callbacks run
// inside it. Not thread-safe, by design.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nbl_h2 nbl_h2_t;
typedef struct nbl_stream nbl_stream_t;

typedef struct {
    /** Response header (also trailers). May be NULL. */
    void (*on_header)(void *ctx, const char *name, const char *value);
    /** One complete gRPC message (without the 5-byte prefix), valid only during the call. */
    void (*on_msg)(void *ctx, const uint8_t *msg, size_t len);
    /** Stream finished; the stream handle is invalid afterwards. grpc_status: -1 = none seen
     *  (transport error), 0 = OK, 4 = DEADLINE_EXCEEDED (see nbl_h2_set_deadline()). */
    void (*on_close)(void *ctx, int grpc_status, const char *grpc_message, uint32_t h2_error);
} nbl_stream_cb_t;

/** TLS connect (ALPN "h2" required) + HTTP/2 connection setup. NULL on error. */
nbl_h2_t *nbl_h2_open(const char *host, int port, int timeout_ms);
void nbl_h2_free(nbl_h2_t *h);
bool nbl_h2_alive(const nbl_h2_t *h);

/** Starts a call. extra_name/extra_value: one optional extra header. */
nbl_stream_t *nbl_h2_call(nbl_h2_t *h, const char *path, const char *extra_name,
                          const char *extra_value, const nbl_stream_cb_t *cb, void *ctx);

/** Appends a gRPC message. msg == NULL sends no message: with last = true a pure half-close.
 *  last = half-close. 0 = queued (sent by nbl_h2_run()), <0 = error. */
int nbl_h2_send(nbl_stream_t *s, const uint8_t *msg, size_t len, bool last);

/** Optional deadline for a call: if it has not finished timeout_ms after this call, it is
 *  cancelled (RST_STREAM) and on_close reports grpc_status 4 (DEADLINE_EXCEEDED). Meant for
 *  short asynchronous calls; without it a call stays open until the server ends it
 *  (long-lived streams such as Sync). Checked in nbl_h2_run(); <= 0 removes the deadline. */
void nbl_h2_set_deadline(nbl_stream_t *s, int timeout_ms);

/** Drives the connection for up to timeout_ms. 0 = ok, <0 = connection dead. */
int nbl_h2_run(nbl_h2_t *h, int timeout_ms);

/** Unary call, blocks until done. *resp is malloc'ed (caller frees).
 *  Returns 0 = OK, -1 = call not started, -2 = timeout/connection lost, -3 = grpc status != 0. */
int nbl_h2_unary(nbl_h2_t *h, const char *path, const uint8_t *req, size_t req_len, uint8_t **resp,
                 size_t *resp_len, int *grpc_status, char *grpc_message, size_t msg_cap, int timeout_ms);

#ifdef __cplusplus
}
#endif
