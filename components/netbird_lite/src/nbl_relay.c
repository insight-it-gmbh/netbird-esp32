// SPDX-License-Identifier: Apache-2.0
#include "nbl_relay.h"
#include "netbird_lite.h"
#include "nbl_relaymsg.h"
#include "nbl_ws.h"

#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/sha1.h"
#include "sdkconfig.h"
#if CONFIG_VFS_SUPPORT_SELECT /* not available with CONFIG_LWIP_USE_ONLY_LWIP_SELECT */
#include "esp_vfs_eventfd.h"
#endif

static const char *TAG = "nbl_relay";

#define MAX_MSG NBL_R_MAX_MSG
#define ACC_CAP (MAX_MSG + 64)
#define WS_HDR_MAX 14 /* 2 + 8 (64-bit length) + 4 (mask) */
#define HOST_CAP 128
#define TXQ_DEPTH 24
#define TX_BUDGET 16                   /* packets sent per loop pass before RX gets its turn */
#define IO_TIMEOUT_US (10 * 1000000LL) /* handshake, auth response, one blocked write */
/* Upstream shared/relay/healthcheck: the server sends a health check every 25 s
 * (defaultHealthCheckInterval) and the client gives up after defaultHeartbeatTimeout =
 * 25 s + 10 s without one. Here any received frame counts. */
#define RX_SILENCE_S 35
/* Reconnect backoff as in the upstream client (shared/relay/client/guard.go: 2 s initial
 * interval, multiplier 2), with +-25 % jitter and capped at 30 s; back to 2 s after a session
 * that was up for at least 60 s. */
#define BACKOFF_MIN_MS 2000
#define BACKOFF_MAX_MS 30000
#define STABLE_SESSION_US (60 * 1000000LL)

/* The counters are written by the relay task and (dropped) by the lwIP tcpip thread. */
#define CNT_ADD(field, v) __atomic_fetch_add(&R.st.field, (uint32_t)(v), __ATOMIC_RELAXED)

struct txm {
    uint8_t *buf;
    uint16_t len;
};

static struct {
    SemaphoreHandle_t mu;
    char url[160], tok_payload[32], tok_sig[96], my_key[NBL_KEY_B64 + 1];
    bool configured;
    volatile bool reconfig; /* URL or key changed: the current session reconnects */
    volatile bool up;
    char instance[160];
    nbl_relay_rx_fn rx;
    QueueHandle_t txq;
    volatile bool stop;
    volatile int efd; /* eventfd that wakes the relay task; -1: none, TX is polled */
    nbl_relay_stats_t st;
    /* Connection state, owned by the relay task */
    esp_tls_t *tls;
    int fd;
    uint8_t *acc;           /* received bytes; acc[acc_off..acc_len) are not parsed yet */
    size_t acc_len, acc_off;
    int64_t last_rx;        /* time of the last received frame */
} R = {.efd = -1, .fd = -1};

static uint8_t msg_buf[MAX_MSG + 32]; /* reassembled message */
static size_t msg_len;
static nbl_ws_t ws;
static uint8_t tx_frame[WS_HDR_MAX + MAX_MSG]; /* only the relay task sends */

/* ---------------- Raw I/O ---------------- */

/* On WANT_READ/WANT_WRITE mbedTLS must be called again with the same data. Gives up after
 * IO_TIMEOUT_US or when the relay is being stopped. */
static int tls_write_all(const uint8_t *d, size_t n)
{
    int64_t end = esp_timer_get_time() + IO_TIMEOUT_US;
    size_t off = 0;
    while (off < n) {
        ssize_t w = esp_tls_conn_write(R.tls, d + off, n - off);
        if (w > 0) {
            off += (size_t)w;
        } else if ((w == ESP_TLS_ERR_SSL_WANT_READ || w == ESP_TLS_ERR_SSL_WANT_WRITE) && !R.stop &&
                   esp_timer_get_time() < end) {
            vTaskDelay(1);
        } else {
            return -1;
        }
    }
    return 0;
}

/* Reads into R.acc after dropping the bytes already parsed. Returns 0 = nothing read (timeout
 * or wake-up through the eventfd), >0 = bytes read, <0 = error/EOF. select() is skipped while
 * mbedTLS still holds decrypted bytes, which the socket would not report as readable. */
static int fill(int timeout_ms)
{
    if (R.acc_off) {
        memmove(R.acc, R.acc + R.acc_off, R.acc_len - R.acc_off);
        R.acc_len -= R.acc_off;
        R.acc_off = 0;
    }
    if (R.acc_len >= ACC_CAP) {
        return -1;
    }
    if (esp_tls_get_bytes_avail(R.tls) <= 0) {
        int efd = R.efd;
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(R.fd, &rf);
        if (efd >= 0) {
            FD_SET(efd, &rf);
        }
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        int r = select((efd > R.fd ? efd : R.fd) + 1, &rf, NULL, NULL, &tv);
        if (r < 0) {
            return -1;
        }
        if (efd >= 0 && FD_ISSET(efd, &rf)) {
            uint64_t v;
            (void)read(efd, &v, sizeof(v)); /* reset the counter; the caller drains the TX queue */
        }
        if (r == 0 || !FD_ISSET(R.fd, &rf)) {
            return 0;
        }
    }
    int n = esp_tls_conn_read(R.tls, R.acc + R.acc_len, ACC_CAP - R.acc_len);
    if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    if (n <= 0) {
        return -1;
    }
    R.acc_len += (size_t)n;
    return n;
}

/* ---------------- WebSocket (RFC 6455, client side only) ---------------- */

static int ws_send(uint8_t opcode, const uint8_t *p, size_t n)
{
    uint8_t mask[4];
    nbl_random(mask, sizeof(mask));
    int fl = nbl_ws_build(opcode, p, n, mask, tx_frame, sizeof(tx_frame));
    return fl < 0 ? -1 : tls_write_all(tx_frame, (size_t)fl);
}

/* Returns 1 for a complete message (msg_buf/msg_len), 0 = more data needed, <0 = closed/error.
 * Iterative: PONGs and fragments are skipped inside nbl_ws_poll(), PINGs are answered here. */
static int ws_next(void)
{
    for (;;) {
        nbl_ws_event_t ev;
        size_t used;
        int r = nbl_ws_poll(&ws, R.acc + R.acc_off, R.acc_len - R.acc_off, &used, &ev);
        if (used) {
            R.acc_off += used;
            R.last_rx = esp_timer_get_time();
        }
        if (r <= 0) {
            return r;
        }
        if (ev.type == NBL_WS_DATA) {
            msg_len = ev.len;
            return 1;
        }
        if (ev.type == NBL_WS_CLOSE) {
            /* Answer with a Close frame that echoes the status code (RFC 6455 5.5.1). */
            ws_send(NBL_WS_OP_CLOSE, ev.data, ev.len >= 2 ? 2 : 0);
            return -1;
        }
        /* PING: ev.data points into R.acc, which only fill() moves, so it is still intact. */
        if (ws_send(NBL_WS_OP_PONG, ev.data, ev.len) < 0) {
            return -1;
        }
    }
}

static int ws_handshake(const char *host, int port)
{
    uint8_t rnd[16];
    char key[32];
    nbl_random(rnd, sizeof(rnd));
    nbl_b64_enc(rnd, sizeof(rnd), key, sizeof(key));
    char req[400];
    int n = snprintf(req, sizeof(req),
                     "GET /relay HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: netbird-lite/" NETBIRD_LITE_VERSION "\r\n\r\n",
                     host, port, key);
    if (n < 0 || n >= (int)sizeof(req) || tls_write_all((const uint8_t *)req, (size_t)n) < 0) {
        return -1;
    }
    /* Expected Sec-WebSocket-Accept: base64(SHA-1(key + GUID)) */
    char cat[80];
    snprintf(cat, sizeof(cat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    uint8_t sha[20];
    mbedtls_sha1((const unsigned char *)cat, strlen(cat), sha);
    char accept[40];
    nbl_b64_enc(sha, sizeof(sha), accept, sizeof(accept));

    int64_t end = esp_timer_get_time() + IO_TIMEOUT_US;
    while (esp_timer_get_time() < end && !R.stop && !R.reconfig) {
        int r = nbl_ws_handshake_response((const char *)R.acc, R.acc_len, accept);
        if (r > 0) {
            R.acc_off = (size_t)r; /* frames may follow the header block */
            return 0;
        }
        if (r < 0) {
            int sl = 0;
            while (sl < 60 && (size_t)sl < R.acc_len && R.acc[sl] != '\r') {
                sl++;
            }
            ESP_LOGE(TAG, "WebSocket upgrade rejected (status line: %.*s)", sl, (const char *)R.acc);
            return -1;
        }
        if (fill(500) < 0) {
            return -1;
        }
    }
    return -1;
}

/* ---------------- Relay protocol ---------------- */

static void free_txq(void)
{
    struct txm m;
    while (xQueueReceive(R.txq, &m, 0) == pdTRUE) {
        free(m.buf);
        CNT_ADD(dropped, 1);
    }
}

/* One connection. Returns 0 if it ended because of nbl_relay_stop() or a configuration change
 * (reconnect at once), -1 otherwise. *up_us receives how long the session was up. */
static int relay_session(int64_t *up_us)
{
    char url[sizeof(R.url)], payload[sizeof(R.tok_payload)], sig[sizeof(R.tok_sig)], key[sizeof(R.my_key)];
    xSemaphoreTake(R.mu, portMAX_DELAY);
    strlcpy(url, R.url, sizeof(url));
    strlcpy(payload, R.tok_payload, sizeof(payload));
    strlcpy(sig, R.tok_sig, sizeof(sig));
    strlcpy(key, R.my_key, sizeof(key));
    R.reconfig = false;
    xSemaphoreGive(R.mu);

    *up_us = 0;
    int64_t up_at = 0;
    /* Fresh state for every connection: no fragment or byte of the previous one survives. */
    nbl_ws_init(&ws, msg_buf, sizeof(msg_buf));
    R.acc_len = 0;
    R.acc_off = 0;

    char host[HOST_CAP];
    uint16_t port;
    if (nbl_relay_parse_url(url, host, sizeof(host), &port) < 0) {
        goto out; /* not reached: nbl_relay_configure() only stores valid URLs */
    }
    esp_tls_cfg_t cfg = {.crt_bundle_attach = esp_crt_bundle_attach, .timeout_ms = 10000};
    R.tls = esp_tls_init();
    if (!R.tls || esp_tls_conn_new_sync(host, strlen(host), port, &cfg, R.tls) != 1 ||
        esp_tls_get_conn_sockfd(R.tls, &R.fd) != ESP_OK) {
        ESP_LOGW(TAG, "TLS connection to %s:%d failed", host, port);
        goto out;
    }
    if (ws_handshake(host, port) < 0) {
        goto out;
    }

    uint8_t sigbin[32];
    int sl = nbl_b64_dec(sig, sigbin, sizeof(sigbin));
    if (sl != 32) {
        ESP_LOGE(TAG, "token signature has %d bytes instead of 32", sl);
        goto out;
    }
    uint8_t peer_id[NBL_RELAY_ID_LEN];
    nbl_relay_id(key, peer_id);
    uint8_t auth[2 + 4 + NBL_RELAY_ID_LEN + 1 + 32 + 64];
    int a = nbl_relay_build_auth(auth, sizeof(auth), peer_id, sigbin, payload);
    if (a < 0 || ws_send(NBL_WS_OP_BINARY, auth, (size_t)a) < 0) {
        goto out;
    }

    /* Wait for the auth response. On auth failure the server closes without a response. */
    int64_t end = esp_timer_get_time() + IO_TIMEOUT_US;
    for (;;) {
        int r = ws_next();
        if (r < 0 || R.stop || R.reconfig) {
            goto out;
        }
        if (r == 1) {
            break;
        }
        if (esp_timer_get_time() >= end) {
            ESP_LOGE(TAG, "auth timed out");
            goto out;
        }
        if (fill(200) < 0) {
            goto out;
        }
    }
    nbl_relay_msg_t rm;
    if (nbl_relay_parse(msg_buf, msg_len, &rm) != 0 || rm.type != NBL_R_AUTH_RESP) {
        ESP_LOGE(TAG, "auth rejected or unexpected response (type %u)", msg_len > 1 ? msg_buf[1] : 0);
        goto out;
    }
    size_t il = rm.payload_len < sizeof(R.instance) - 1 ? rm.payload_len : sizeof(R.instance) - 1;
    xSemaphoreTake(R.mu, portMAX_DELAY);
    memcpy(R.instance, rm.payload, il);
    R.instance[il] = 0;
    xSemaphoreGive(R.mu);
    ESP_LOGI(TAG, "relay connected, instance %s", R.instance);
    up_at = R.last_rx = esp_timer_get_time();
    R.up = true;

    /* Connected: main loop */
    for (;;) {
        if (R.stop || R.reconfig) {
            /* Graceful end: tell the server, as the upstream client does (writeCloseMsg). */
            static const uint8_t bye[2] = {NBL_R_PROTO, NBL_R_CLOSE};
            ws_send(NBL_WS_OP_BINARY, bye, sizeof(bye));
            break;
        }
        /* TX */
        struct txm m;
        for (int budget = TX_BUDGET; budget > 0 && xQueueReceive(R.txq, &m, 0) == pdTRUE; budget--) {
            int w = ws_send(NBL_WS_OP_BINARY, m.buf, m.len);
            free(m.buf);
            if (w < 0) {
                CNT_ADD(dropped, 1);
                goto out;
            }
            CNT_ADD(tx_pkts, 1);
            CNT_ADD(tx_bytes, m.len);
        }
        /* RX */
        int r;
        while ((r = ws_next()) == 1) {
            if (nbl_relay_parse(msg_buf, msg_len, &rm) != 0) {
                CNT_ADD(dropped, 1); /* unknown or client-only type, oversize transport payload */
            } else if (rm.type == NBL_R_TRANSPORT) {
                CNT_ADD(rx_pkts, 1);
                CNT_ADD(rx_bytes, msg_len);
                if (R.rx) {
                    R.rx(rm.id, rm.payload, rm.payload_len);
                }
            } else if (rm.type == NBL_R_HEALTH) {
                /* Echo the health check; the server drops peers that do not answer. */
                static const uint8_t hc[2] = {NBL_R_PROTO, NBL_R_HEALTH};
                if (ws_send(NBL_WS_OP_BINARY, hc, sizeof(hc)) < 0) {
                    goto out;
                }
            } else if (rm.type == NBL_R_CLOSE) {
                ESP_LOGW(TAG, "relay server is closing the connection");
                goto out;
            }
        }
        if (r < 0) {
            goto out;
        }
        if (esp_timer_get_time() - R.last_rx > RX_SILENCE_S * 1000000LL) {
            ESP_LOGW(TAG, "nothing received from the relay for %d s, reconnecting", RX_SILENCE_S);
            goto out;
        }
        /* Sleep until data arrives or nbl_relay_send() wakes us, but not while TX is pending. */
        int wait_ms = uxQueueMessagesWaiting(R.txq) ? 0 : R.efd >= 0 ? 1000 : 10;
        if (fill(wait_ms) < 0) {
            goto out;
        }
    }
out:
    if (R.up) {
        *up_us = esp_timer_get_time() - up_at;
    }
    R.up = false;
    xSemaphoreTake(R.mu, portMAX_DELAY);
    R.instance[0] = 0;
    xSemaphoreGive(R.mu);
    if (R.tls) {
        esp_tls_conn_destroy(R.tls);
        R.tls = NULL;
    }
    R.fd = -1;
    free_txq();
    return R.stop || R.reconfig ? 0 : -1;
}

/* The eventfd lets nbl_relay_send() wake the relay task out of select() at once. Without it
 * (no VFS select support, registration failed) the task polls the TX queue every 10 ms. It is
 * never closed: other threads may still write to it. */
static void efd_open(void)
{
#if CONFIG_VFS_SUPPORT_SELECT
    esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    esp_err_t e = esp_vfs_eventfd_register(&cfg);
    /* ESP_ERR_INVALID_STATE: the application has registered the eventfd VFS already */
    if (e == ESP_OK || e == ESP_ERR_INVALID_STATE) {
        R.efd = eventfd(0, 0);
    }
#endif
    if (R.efd < 0) {
        ESP_LOGW(TAG, "no eventfd available, relay TX is polled every 10 ms");
    }
}

static void wake(void)
{
    int efd = R.efd;
    if (efd >= 0) {
        uint64_t one = 1;
        (void)write(efd, &one, sizeof(one));
    }
}

static void relay_task(void *arg)
{
    (void)arg;
    efd_open();
    int backoff_ms = BACKOFF_MIN_MS;
    while (!R.stop) {
        xSemaphoreTake(R.mu, portMAX_DELAY);
        bool ok = R.configured;
        xSemaphoreGive(R.mu);
        if (!ok) {
            vTaskDelay(pdMS_TO_TICKS(300));
            continue;
        }
        int64_t up_us;
        if (relay_session(&up_us) == 0) {
            backoff_ms = BACKOFF_MIN_MS;
            continue; /* stopped, or reconfigured: reconnect at once */
        }
        if (up_us >= STABLE_SESSION_US) {
            backoff_ms = BACKOFF_MIN_MS;
        }
        CNT_ADD(reconnects, 1);
        /* +-25 % jitter, so that many devices do not reconnect in lockstep */
        int wait_ms = backoff_ms - backoff_ms / 4 + (int)(esp_random() % (uint32_t)(backoff_ms / 2 + 1));
        if (wait_ms > BACKOFF_MAX_MS) {
            wait_ms = BACKOFF_MAX_MS;
        }
        ESP_LOGW(TAG, "relay connection ended, retrying in %d ms", wait_ms);
        for (int i = 0; i < wait_ms / 100 && !R.stop && !R.reconfig; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        backoff_ms = backoff_ms < BACKOFF_MAX_MS / 2 ? backoff_ms * 2 : BACKOFF_MAX_MS;
    }
    vTaskDelete(NULL);
}

/* ---------------- API ---------------- */

esp_err_t nbl_relay_start(nbl_relay_rx_fn rx)
{
    if (R.mu) {
        return ESP_ERR_INVALID_STATE; /* started before; there is no restart */
    }
    R.rx = rx;
    R.mu = xSemaphoreCreateMutex();
    R.txq = xQueueCreate(TXQ_DEPTH, sizeof(struct txm));
    R.acc = malloc(ACC_CAP);
    if (R.mu && R.txq && R.acc &&
        xTaskCreate(relay_task, "nbl_relay", CONFIG_NBL_RELAY_STACK, NULL, 5, NULL) == pdPASS) {
        return ESP_OK;
    }
    free(R.acc);
    R.acc = NULL;
    if (R.txq) {
        vQueueDelete(R.txq);
        R.txq = NULL;
    }
    if (R.mu) {
        vSemaphoreDelete(R.mu);
        R.mu = NULL;
    }
    return ESP_ERR_NO_MEM;
}

void nbl_relay_stop(void)
{
    R.stop = true;
    wake();
}

void nbl_relay_configure(const char *url, const char *payload, const char *sig, const char *my_key)
{
    char host[HOST_CAP];
    uint16_t port;
    if (strlen(url) >= sizeof(R.url) || strlen(payload) >= sizeof(R.tok_payload) ||
        strlen(sig) >= sizeof(R.tok_sig) || strlen(my_key) >= sizeof(R.my_key) ||
        nbl_relay_parse_url(url, host, sizeof(host), &port) < 0) {
        ESP_LOGE(TAG, "relay configuration ignored: unsupported URL (rels://host[:port] only) or a value "
                      "too long: %.80s", url);
        return;
    }
    if (!R.mu) {
        return;
    }
    xSemaphoreTake(R.mu, portMAX_DELAY);
    bool changed = strcmp(R.url, url) != 0 || strcmp(R.my_key, my_key) != 0;
    strlcpy(R.url, url, sizeof(R.url));
    strlcpy(R.tok_payload, payload, sizeof(R.tok_payload));
    strlcpy(R.tok_sig, sig, sizeof(R.tok_sig));
    strlcpy(R.my_key, my_key, sizeof(R.my_key));
    /* A session that is up or still connecting reconnects with the new values; a backoff
     * wait ends early. The session copies the configuration under R.mu. */
    if (changed) {
        R.reconfig = true;
    }
    R.configured = true;
    xSemaphoreGive(R.mu);
    if (changed) {
        wake();
    }
}

bool nbl_relay_up(void)
{
    return R.up;
}

void nbl_relay_get_instance(char *out, size_t cap)
{
    if (!cap) {
        return;
    }
    out[0] = 0;
    if (!R.mu) {
        return;
    }
    xSemaphoreTake(R.mu, portMAX_DELAY);
    strlcpy(out, R.instance, cap);
    xSemaphoreGive(R.mu);
}

const char *nbl_relay_instance(void)
{
    static char copy[sizeof(R.instance)];
    nbl_relay_get_instance(copy, sizeof(copy));
    return copy;
}

int nbl_relay_send(const uint8_t dst_id[NBL_RELAY_ID_LEN], const uint8_t *wg, size_t len)
{
    struct txm m = {NULL, 0};
    if (R.up && len <= MAX_MSG - 2 - NBL_RELAY_ID_LEN) {
        m.len = (uint16_t)(2 + NBL_RELAY_ID_LEN + len);
        m.buf = malloc(m.len);
    }
    if (!m.buf || nbl_relay_build_transport(m.buf, m.len, dst_id, wg, len) < 0 ||
        xQueueSend(R.txq, &m, 0) != pdTRUE) {
        free(m.buf);
        CNT_ADD(dropped, 1);
        return -1;
    }
    wake();
    return 0;
}

void nbl_relay_stats(nbl_relay_stats_t *s)
{
    s->rx_pkts = __atomic_load_n(&R.st.rx_pkts, __ATOMIC_RELAXED);
    s->tx_pkts = __atomic_load_n(&R.st.tx_pkts, __ATOMIC_RELAXED);
    s->rx_bytes = __atomic_load_n(&R.st.rx_bytes, __ATOMIC_RELAXED);
    s->tx_bytes = __atomic_load_n(&R.st.tx_bytes, __ATOMIC_RELAXED);
    s->reconnects = __atomic_load_n(&R.st.reconnects, __ATOMIC_RELAXED);
    s->dropped = __atomic_load_n(&R.st.dropped, __ATOMIC_RELAXED);
}
