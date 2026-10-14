// libFuzzer target for the HTTP/2 core: frame parser, HPACK decoder (including Huffman), flow
// control and the send queue. As in the transport, the output is drained after every input
// chunk, so long sessions are explored; callbacks and some input bytes act on the connection
// the way the gRPC glue and the application do (reset a stream, start a call, send).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nbl_h2p.h"

static nbl_h2p_t H;
static nbl_h2p_stream_t SLOTS[8];
static uint8_t BODY[70000]; /* larger than the initial windows and the send queue */
static const nbl_h2p_hdr_t HDRS[] = {{":method", "POST"}, {":path", "/x"}};

static void call(void)
{
    uint32_t id;
    if (nbl_h2p_open_stream(&H, HDRS, 2, true, &id) == 0) {
        nbl_h2p_send_data(&H, id, BODY, 400, true);
    }
}

static void cb_hdr(void *c, uint32_t id, const char *n, const char *v) { (void)c; (void)id; (void)n; (void)v; }
static void cb_hdrd(void *c, uint32_t id, bool e) { (void)c; (void)id; (void)e; }
static void cb_data(void *c, uint32_t id, const uint8_t *d, size_t l, bool e)
{
    (void)c;
    (void)e;
    if (l && d[0] == 'R') {
        nbl_h2p_reset(&H, id); /* like the glue on a gRPC framing error */
    } else if (l && d[0] == 'O') {
        call(); /* like an answer sent from a message callback */
    }
}
static void cb_close(void *c, uint32_t id, uint32_t e)
{
    (void)c;
    (void)id;
    if (e == 7) {
        call();
    }
}
static void cb_go(void *c, uint32_t a, uint32_t b) { (void)c; (void)a; (void)b; }
static void cb_err(void *c, const char *w) { (void)c; (void)w; }
static const nbl_h2p_cb_t CB = {cb_hdr, cb_hdrd, cb_data, cb_close, cb_go, cb_err};

static void drain(void)
{
    uint8_t tmp[1024];
    while (nbl_h2p_want_write(&H)) {
        nbl_h2p_output(&H, tmp, sizeof(tmp));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 32768) return 0;
    nbl_h2p_init(&H, &CB, NULL, SLOTS, 8);
    nbl_h2p_start(&H);
    /* the server preface (SETTINGS) is synthesized so that every input reaches the frame handlers */
    static const uint8_t settings[9] = {0, 0, 0, 4, 0, 0, 0, 0, 0};
    nbl_h2p_input(&H, settings, sizeof(settings));
    /* stream 1: large request body waiting for window updates, stream 3: open, nothing sent,
       stream 5: half-closed. The input may address any stream ID. */
    uint32_t id;
    if (nbl_h2p_open_stream(&H, HDRS, 2, true, &id) == 0) {
        nbl_h2p_send_data(&H, id, BODY, sizeof(BODY), true);
    }
    nbl_h2p_open_stream(&H, HDRS, 2, true, &id);
    nbl_h2p_open_stream(&H, HDRS, 2, false, &id);
    drain();
    /* feed the input in chunks whose sizes are derived from the input */
    size_t off = 0;
    while (off < size) {
        uint8_t ctl = data[off];
        size_t step = 1 + ctl % 251;
        if (step > size - off) step = size - off;
        int used = nbl_h2p_input(&H, data + off, step);
        if (used < 0) break;
        off += (size_t)used;
        switch (ctl) { /* the application acts between two reads */
        case 251: call(); break;
        case 252: nbl_h2p_ping(&H); break;
        case 253: nbl_h2p_reset(&H, 1); break;
        case 254: nbl_h2p_end_stream(&H, 3); break;
        case 255: /* two messages: the second is appended while the first still waits */
            nbl_h2p_send_data(&H, 3, BODY, 5000, false);
            nbl_h2p_send_data(&H, 3, BODY, 300, false);
            break;
        default: break;
        }
        drain();
    }
    nbl_h2p_free(&H);
    return 0;
}
