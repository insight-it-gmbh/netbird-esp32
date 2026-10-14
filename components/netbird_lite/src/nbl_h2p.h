// SPDX-License-Identifier: MIT
// Minimal HTTP/2 client core (RFC 9113) + HPACK (RFC 7541): pure, no sockets, host-testable.
// Only what gRPC to NetBird needs: HEADERS/DATA/SETTINGS/PING/WINDOW_UPDATE/RST_STREAM/
// GOAWAY/CONTINUATION; no server push, no priorities. HPACK: static table + Huffman,
// dynamic table deliberately disabled (we announce HEADER_TABLE_SIZE=0).
//
// Send queue: fixed size, every frame is queued whole or not at all. DATA is buffered per
// stream and moved into the queue as flow control and queue space allow (nbl_h2p_output()
// refills the queue), so messages of any size go out in chunks. nbl_h2p_input() stops early
// when the queue gets too full for the frames that answer received ones (PING/SETTINGS ACK,
// RST_STREAM); the caller then sends the queued bytes and passes the rest again.
// WINDOW_UPDATEs for received DATA are coalesced: at most one per stream and one for the
// connection per nbl_h2p_input() call.
// Header blocks are decoded field by field as they arrive, so their size is not limited;
// fields too long for the decoder's buffers (name > 127, value > 383 bytes) are dropped.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NBL_H2P_MAX_FRAME 16384   /* largest frame we accept (default SETTINGS_MAX_FRAME_SIZE) */
#define NBL_H2P_MAX_HDRBLK 1024   /* undecoded part of a header block (one field at most) */
#define NBL_H2P_OUT_CAP 4096      /* internal send queue */
#define NBL_H2P_RESERVE 256       /* queue space HEADERS/DATA leave free for control frames */
#define NBL_H2P_MAX_HDRLIST 65536 /* announced SETTINGS_MAX_HEADER_LIST_SIZE */

typedef struct {
    const char *name;
    const char *value;
} nbl_h2p_hdr_t;

typedef struct {
    void (*on_header)(void *ctx, uint32_t id, const char *name, const char *value);
    void (*on_headers_done)(void *ctx, uint32_t id, bool end_stream);
    void (*on_data)(void *ctx, uint32_t id, const uint8_t *data, size_t len, bool end_stream);
    /* Once per stream when the server ends it: END_STREAM (err 0) or RST_STREAM (its error
       code). The stream is gone already. Not called for nbl_h2p_reset(). */
    void (*on_stream_closed)(void *ctx, uint32_t id, uint32_t err);
    void (*on_goaway)(void *ctx, uint32_t last_stream, uint32_t err);
    void (*on_error)(void *ctx, const char *why);
} nbl_h2p_cb_t;

typedef struct {
    bool used, local_ended; /* local_ended: END_STREAM sent */
    uint32_t id;
    int32_t send_window;
    uint32_t recv_credit; /* received DATA not yet returned with WINDOW_UPDATE */
    uint8_t *pending;     /* DATA not queued yet (flow control or full send queue) */
    size_t pending_len, pending_off;
    bool pending_end; /* END_STREAM requested, not queued yet */
} nbl_h2p_stream_t;

typedef struct nbl_h2p {
    nbl_h2p_cb_t cb;
    void *ctx;
    /* receive */
    uint8_t rx[9 + NBL_H2P_MAX_FRAME];
    size_t rx_len;
    uint8_t hdrblk[NBL_H2P_MAX_HDRBLK]; /* header block bytes not decoded yet */
    size_t hdrblk_len;
    uint64_t hp_skip;   /* bytes of an oversized string still to drop */
    bool hp_skip_value; /* then the value of that (dropped) field follows */
    bool hp_started;    /* a field was decoded: no dynamic table size update any more */
    uint32_t hdrblk_stream;
    uint8_t hdrblk_flags;
    bool in_header_block;
    bool hdrblk_ignore; /* server-initiated stream: decoded, not reported */
    bool preface_ok;    /* the server's SETTINGS frame has arrived */
    uint32_t conn_credit; /* connection-level WINDOW_UPDATE credit not sent yet */
    /* send */
    uint8_t out[NBL_H2P_OUT_CAP];
    size_t out_len;
    int32_t conn_send_window;
    int32_t peer_init_window;
    uint32_t peer_max_frame;
    uint32_t next_stream;
    nbl_h2p_stream_t *streams;
    uint32_t streams_cap;
    bool dead;
} nbl_h2p_t;

int nbl_h2p_init(nbl_h2p_t *h, const nbl_h2p_cb_t *cb, void *ctx, nbl_h2p_stream_t *streams, uint32_t streams_cap);
int nbl_h2p_start(nbl_h2p_t *h); /* queues preface + SETTINGS */
void nbl_h2p_free(nbl_h2p_t *h); /* frees buffered stream data (h itself belongs to the caller) */

/* Returns the number of bytes consumed: less than len when the send queue is too full for
   the answers to further frames; send the output, then pass the rest again.
   <0 = connection error, the connection is unusable. */
int nbl_h2p_input(nbl_h2p_t *h, const uint8_t *data, size_t len);

/* output: fetch queued bytes (0 = none); fetched bytes leave the queue and buffered DATA
   moves up. Call until nbl_h2p_want_write() is false. */
size_t nbl_h2p_output(nbl_h2p_t *h, uint8_t *dst, size_t cap);
bool nbl_h2p_want_write(const nbl_h2p_t *h);

/* -1 also when the HEADERS frame does not fit into the send queue right now: send the
   output and try again. */
int nbl_h2p_open_stream(nbl_h2p_t *h, const nbl_h2p_hdr_t *hdrs, size_t n, bool has_body, uint32_t *id_out);
/* Appends DATA (len 0 with end: END_STREAM only, as an empty DATA frame).
   0 = completely queued, 1 = (partly) buffered, goes out as the windows and the queue
   allow, <0 error (nothing queued). */
int nbl_h2p_send_data(nbl_h2p_t *h, uint32_t id, const uint8_t *data, size_t len, bool end);
int nbl_h2p_end_stream(nbl_h2p_t *h, uint32_t id); /* = nbl_h2p_send_data(h, id, NULL, 0, true) */
/* RST_STREAM(CANCEL), the stream is forgotten (no on_stream_closed). 0 if it is not open. */
int nbl_h2p_reset(nbl_h2p_t *h, uint32_t id);
int nbl_h2p_ping(nbl_h2p_t *h); /* -1 if the send queue is full */
bool nbl_h2p_stream_open(const nbl_h2p_t *h, uint32_t id);
bool nbl_h2p_can_send(const nbl_h2p_t *h, uint32_t id); /* open, window > 0, nothing buffered */

#ifdef __cplusplus
}
#endif
