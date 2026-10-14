// libFuzzer target for the pure parsers: nbl_ws_next, nbl_relay_parse, nbl_grpc_rx_feed, nbl_acl_match.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nbl_ws.h"
#include "nbl_relaymsg.h"
#include "nbl_grpc.h"
#include "nbl_acl.h"

static uint8_t wbuf[16384];
static uint8_t wmsg[16384]; /* WS reassembly buffer - MUST be separate from the input buffer */

static void dummy_cb(void *ctx, const uint8_t *m, size_t n) { (void)ctx; (void)m; (void)n; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 8192) return 0;

    /* 1. WebSocket: the input as a server byte stream. Masked frames are unmasked in place,
          hence the copy into a writable buffer. */
    {
        nbl_ws_t st; nbl_ws_init(&st, wmsg, sizeof(wmsg));
        nbl_ws_event_t ev;
        memcpy(wbuf, data, size);
        size_t off = 0, len = size;
        while (len > 0) {
            int r = nbl_ws_next(&st, wbuf + off, len, &ev);
            if (r <= 0) break;
            off += r; len -= r;
        }
    }
    /* 2. relay message parser */
    {
        nbl_relay_msg_t m;
        nbl_relay_parse(data, size, &m);
    }
    /* 3. gRPC message reassembly, chunk sizes derived from the input */
    {
        nbl_grpc_rx_t st; nbl_grpc_rx_init(&st, 4096);
        size_t off = 0;
        while (off < size) {
            size_t step = 1 + (data[off] % 7);
            if (step > size - off) step = size - off;
            if (nbl_grpc_rx_feed(&st, dummy_cb, NULL, data + off, step) < 0) break;
            off += step;
        }
        nbl_grpc_rx_free(&st);
    }
    /* 4. ACL: bytes 0-12 form one rule, bytes 13-16 the source address; protocol,
          has_port, destination port and the rule action reuse bytes 0-3 */
    if (size >= 17) {
        nbl_acl_rule_t r = {0};
        memcpy(&r.src, data + 0, 4); memcpy(&r.mask, data + 4, 4);
        r.proto = data[8]; memcpy(&r.p0, data + 9, 2); memcpy(&r.p1, data + 11, 2);
        if (r.p0 > r.p1) { uint16_t t = r.p0; r.p0 = r.p1; r.p1 = t; }
        r.action = data[2] >> 1;
        uint32_t src; memcpy(&src, data + 13, 4);
        nbl_acl_match(&r, 1, src, data[3], data[2] & 1, (uint16_t)((data[0] << 8) | data[1]));
    }
    return 0;
}
