// SPDX-License-Identifier: Apache-2.0
// Pure WebSocket framing functions (RFC 6455, client side). No dependencies, so they can be
// tested directly on the host.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opcodes used by the client. Text frames are not: the relay only exchanges binary messages. */
#define NBL_WS_OP_BINARY 0x2
#define NBL_WS_OP_CLOSE 0x8
#define NBL_WS_OP_PING 0x9
#define NBL_WS_OP_PONG 0xA

typedef enum {
    NBL_WS_DATA = 1,   /* complete (possibly reassembled) message */
    NBL_WS_PING,
    NBL_WS_PONG,
    NBL_WS_CLOSE,      /* peer is closing the connection; data holds the status code (or len 0) */
    NBL_WS_NEED_MORE,  /* fragment consumed, message incomplete; keep the state */
    NBL_WS_ERROR = -1  /* malformed frame */
} nbl_ws_event_type_t;

typedef struct {
    nbl_ws_event_type_t type;
    /* Points into acc (control frames) or msg (DATA). Valid until the next call; for control
     * frames only until the caller moves or overwrites acc. */
    const uint8_t *data;
    size_t len;
} nbl_ws_event_t;

/* Reassembly state for fragmented messages. The caller provides msg/msg_cap; msg must not
 * overlap the receive buffer. */
typedef struct {
    uint8_t *msg;
    size_t msg_cap;
    size_t msg_len;
    bool in_msg;
} nbl_ws_t;

/* Resets the state. Call at the start of every connection. */
void nbl_ws_init(nbl_ws_t *st, uint8_t *msg_buf, size_t msg_cap);

/* Parses ONE server frame from acc[0..acc_len). Returns the number of bytes consumed (>0) when
 * an event was produced, 0 = incomplete (call again once more data has arrived), <0 = protocol
 * error. Rejected as errors: RSV bits, masked frames, text and reserved opcodes, control frames
 * that are fragmented or carry more than 125 bytes, a 1-byte close payload, non-minimal
 * length encodings, frames above 64 KiB, fragments out of sequence and messages larger than
 * msg_cap (detected from the header, before the payload has arrived). */
int nbl_ws_next(nbl_ws_t *st, const uint8_t *acc, size_t acc_len, nbl_ws_event_t *ev);

/* Like nbl_ws_next(), but loops over the frames in acc[0..acc_len) until one needs the
 * caller's attention: a complete data message, a PING (answer it with a PONG carrying
 * ev->data) or a CLOSE. PONG frames and message fragments are consumed silently.
 * *used receives the number of bytes consumed, also when 0 or -1 is returned.
 * Returns 1 = event in *ev, 0 = more data needed, -1 = protocol error. */
int nbl_ws_poll(nbl_ws_t *st, const uint8_t *acc, size_t acc_len, size_t *used, nbl_ws_event_t *ev);

/* Builds a masked client frame in out (capacity out_cap). Returns its length or -1.
 * mask == NULL uses a fixed mask (tests only). */
int nbl_ws_build(uint8_t opcode, const uint8_t *payload, size_t len, const uint8_t mask[4],
                 uint8_t *out, size_t out_cap);

/* Checks the server's answer to the opening handshake; buf[0..len) is the response received
 * so far (no NUL terminator needed). Requires the status line "HTTP/1.1 101", an Upgrade
 * header with the token "websocket", a Connection header with the token "upgrade" (both
 * ASCII case-insensitive) and a Sec-WebSocket-Accept header whose whole value equals accept.
 * Returns the length of the header block (through the empty line) if it is complete and
 * valid, 0 if it is still incomplete, -1 if it is invalid. */
int nbl_ws_handshake_response(const char *buf, size_t len, const char *accept);

#ifdef __cplusplus
}
#endif
