// SPDX-License-Identifier: MIT
// NetBird relay client (WebSocket transport, relay protocol version 1). Transport only:
// auth, payload (raw WireGuard packets) and health check. No ICE, no QUIC.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "nbl_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Called from the relay task for every received transport message; wg is only valid during the call. */
typedef void (*nbl_relay_rx_fn)(const uint8_t src_id[NBL_RELAY_ID_LEN], const uint8_t *wg, size_t len);

/** Starts the relay task. Can be called once: later calls return ESP_ERR_INVALID_STATE (there is
 *  no restart after nbl_relay_stop()). On failure nothing stays allocated and the call may be retried. */
esp_err_t nbl_relay_start(nbl_relay_rx_fn rx);
void nbl_relay_stop(void);

/** Sets/updates the relay URL and token (management delivers both in Sync). Thread-safe. A URL that
 *  nbl_relay_parse_url() rejects, or a value too long for the internal buffers, is logged and
 *  ignored (the previous configuration stays). A changed URL or key restarts a running or
 *  connecting session. */
void nbl_relay_configure(const char *url, const char *token_payload, const char *token_sig_b64,
                         const char *my_key_b64);

bool nbl_relay_up(void);
/** Copies our own relay instance URL (from the auth response) into out; "" while not connected.
 *  Thread-safe; the result is truncated to cap - 1 characters. */
void nbl_relay_get_instance(char *out, size_t cap);
/** Deprecated: returns a static copy that the next call overwrites, so it is only safe with a
 *  single caller. Use nbl_relay_get_instance(). */
__attribute__((deprecated("use nbl_relay_get_instance()"))) const char *nbl_relay_instance(void);
/** Queues a WireGuard packet for sending (the data is copied). 0 = queued, <0 = dropped. */
int nbl_relay_send(const uint8_t dst_id[NBL_RELAY_ID_LEN], const uint8_t *wg, size_t len);

typedef struct {
    /* dropped: TX packets that could not be queued or sent, and received messages that were
     * rejected (unknown type, oversize transport payload) */
    uint32_t rx_pkts, tx_pkts, rx_bytes, tx_bytes, reconnects, dropped;
} nbl_relay_stats_t;
void nbl_relay_stats(nbl_relay_stats_t *s);

#ifdef __cplusplus
}
#endif
