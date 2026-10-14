// SPDX-License-Identifier: Apache-2.0
// Transport: esp-tls <-> nbl_h2p, plus gRPC framing (nbl_grpc) and the public nbl_h2 API.
// Built instead of nbl_h2.c when CONFIG_NBL_H2_LITE=y.
#include "nbl_h2.h"
#include "netbird_lite.h"

#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ssl.h"
#include "nbl_grpc.h"
#include "nbl_h2p.h"

#ifndef CONFIG_MBEDTLS_SSL_ALPN
#error "netbird-lite needs CONFIG_MBEDTLS_SSL_ALPN: HTTP/2 is negotiated via ALPN"
#endif

static const char *TAG = "nbl_h2l";

#define MAX_STREAMS 8
#define MAX_GRPC_MSG (48 * 1024)
/* Keep the PING interval >= 15 s: NetBird management enforces a keepalive MinTime of 15 s
 * and answers more frequent pings with GOAWAY (too_many_pings). */
#define PING_EVERY_US (20LL * 1000000)
/* no bytes received for this long -> connection considered dead (our PINGs get ACKed) */
#define DEAD_AFTER_US (70LL * 1000000)

struct nbl_stream {
    nbl_h2_t *h;
    uint32_t id;
    bool used;
    nbl_stream_cb_t cb;
    void *ctx;
    nbl_grpc_rx_t rx;
    int64_t deadline_us; /* 0 = none */
    int grpc_status;
    char grpc_msg[96];
};

struct nbl_h2 {
    esp_tls_t *tls;
    int fd;
    nbl_h2p_t proto;
    nbl_h2p_stream_t slots[MAX_STREAMS];
    nbl_stream_t streams[MAX_STREAMS];
    bool dead;
    int64_t last_ping_us, last_rx_us;
    char authority[160];
    uint8_t txbuf[1024]; /* output -> TLS; not on the stack, flush_out() also runs in callbacks */
};

/* ---------------- stream lookup ---------------- */

static nbl_stream_t *stream_by_id(nbl_h2_t *h, uint32_t id)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (h->streams[i].used && h->streams[i].id == id) {
            return &h->streams[i];
        }
    }
    return NULL;
}

static void close_stream(nbl_stream_t *s, int grpc_status, const char *msg, uint32_t h2err)
{
    if (s->cb.on_close) {
        s->cb.on_close(s->ctx, grpc_status, msg ? msg : "", h2err);
    }
    nbl_grpc_rx_free(&s->rx);
    memset(s, 0, sizeof(*s));
}

/* Ends a call without on_close (the caller reports the outcome itself). */
static void drop_call(nbl_h2_t *h, nbl_stream_t *s)
{
    nbl_h2p_reset(&h->proto, s->id);
    nbl_grpc_rx_free(&s->rx);
    memset(s, 0, sizeof(*s));
}

/* Writes everything the protocol core has queued; buffered DATA follows as space frees up. */
static int flush_out(nbl_h2_t *h)
{
    while (nbl_h2p_want_write(&h->proto)) {
        size_t n = nbl_h2p_output(&h->proto, h->txbuf, sizeof(h->txbuf));
        for (size_t off = 0; off < n;) {
            int w = esp_tls_conn_write(h->tls, (const char *)h->txbuf + off, n - off);
            if (w > 0) {
                off += (size_t)w;
            } else if (w == ESP_TLS_ERR_SSL_WANT_READ || w == ESP_TLS_ERR_SSL_WANT_WRITE) {
                vTaskDelay(1);
            } else {
                ESP_LOGW(TAG, "write error: %d", w);
                h->dead = true;
                return -1;
            }
        }
    }
    return 0;
}

/* ---------------- protocol callbacks ---------------- */

static void p_header(void *ctx, uint32_t id, const char *n, const char *v)
{
    nbl_stream_t *s = stream_by_id(ctx, id);
    if (!s) {
        return;
    }
    if (!strcmp(n, "grpc-status")) {
        s->grpc_status = atoi(v);
    } else if (!strcmp(n, "grpc-message")) {
        strlcpy(s->grpc_msg, v, sizeof(s->grpc_msg));
    }
    if (s->cb.on_header) {
        s->cb.on_header(s->ctx, n, v);
    }
}

static void grpc_msg(void *ctx, const uint8_t *m, size_t len)
{
    nbl_stream_t *s = ctx;
    if (s->cb.on_msg) {
        s->cb.on_msg(s->ctx, m, len);
    }
}

static void p_data(void *ctx, uint32_t id, const uint8_t *d, size_t len, bool end)
{
    (void)end; /* the end of the stream is reported through p_closed() */
    nbl_h2_t *h = ctx;
    nbl_stream_t *s = stream_by_id(h, id);
    if (!s) {
        return;
    }
    if (nbl_grpc_rx_feed(&s->rx, grpc_msg, s, d, len) < 0) {
        ESP_LOGW(TAG, "broken gRPC framing, dropping stream %u", (unsigned)id);
        nbl_h2p_reset(&h->proto, id);
        close_stream(s, -1, "grpc framing", 0);
    }
}

static void p_closed(void *ctx, uint32_t id, uint32_t err)
{
    nbl_stream_t *s = stream_by_id(ctx, id);
    if (!s) {
        return;
    }
    close_stream(s, s->grpc_status, s->grpc_msg, err);
}

static void p_goaway(void *ctx, uint32_t last, uint32_t err)
{
    nbl_h2_t *h = ctx;
    ESP_LOGW(TAG, "GOAWAY received (last stream %u, error %u)", (unsigned)last, (unsigned)err);
    h->dead = true;
}

static void p_error(void *ctx, const char *why)
{
    nbl_h2_t *h = ctx;
    ESP_LOGW(TAG, "protocol error: %s", why);
    h->dead = true;
}

/* ---------------- public API ---------------- */

static bool alpn_is_h2(esp_tls_t *tls)
{
    const mbedtls_ssl_context *ssl = esp_tls_get_ssl_context(tls);
    const char *p = ssl ? mbedtls_ssl_get_alpn_protocol(ssl) : NULL;
    return p && !strcmp(p, "h2");
}

nbl_h2_t *nbl_h2_open(const char *host, int port, int timeout_ms)
{
    nbl_h2_t *h = calloc(1, sizeof(*h));
    if (!h) {
        return NULL;
    }
    static const char *alpn[] = {"h2", NULL};
    esp_tls_cfg_t cfg = {
        .alpn_protos = alpn,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = timeout_ms,
    };
    h->tls = esp_tls_init();
    bool ok = h->tls && esp_tls_conn_new_sync(host, strlen(host), port, &cfg, h->tls) == 1;
    if (!ok) {
        ESP_LOGE(TAG, "TLS connection to %s:%d failed", host, port);
    } else if (!alpn_is_h2(h->tls)) {
        ESP_LOGE(TAG, "%s:%d: server did not negotiate HTTP/2 (ALPN)", host, port);
        ok = false;
    }
    nbl_h2p_cb_t cb = {.on_header = p_header, .on_data = p_data, .on_stream_closed = p_closed,
                       .on_goaway = p_goaway, .on_error = p_error};
    if (ok && (nbl_h2p_init(&h->proto, &cb, h, h->slots, MAX_STREAMS) < 0 || nbl_h2p_start(&h->proto) < 0)) {
        ok = false;
    }
    if (!ok) {
        if (h->tls) {
            esp_tls_conn_destroy(h->tls);
        }
        free(h);
        return NULL;
    }
    esp_tls_get_conn_sockfd(h->tls, &h->fd);
    snprintf(h->authority, sizeof(h->authority), "%s:%d", host, port);
    h->last_rx_us = h->last_ping_us = esp_timer_get_time();
    return h;
}

void nbl_h2_free(nbl_h2_t *h)
{
    if (!h) {
        return;
    }
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (h->streams[i].used) {
            nbl_grpc_rx_free(&h->streams[i].rx);
        }
    }
    nbl_h2p_free(&h->proto); /* request data still buffered per stream */
    if (h->tls) {
        esp_tls_conn_destroy(h->tls);
    }
    free(h);
}

bool nbl_h2_alive(const nbl_h2_t *h)
{
    return h && !h->dead;
}

nbl_stream_t *nbl_h2_call(nbl_h2_t *h, const char *path, const char *xn, const char *xv,
                          const nbl_stream_cb_t *cb, void *ctx)
{
    if (h->dead) {
        return NULL;
    }
    nbl_stream_t *s = NULL;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!h->streams[i].used) {
            s = &h->streams[i];
            break;
        }
    }
    if (!s) {
        return NULL;
    }
    memset(s, 0, sizeof(*s));
    s->used = true;
    s->h = h;
    s->cb = *cb;
    s->ctx = ctx;
    s->grpc_status = -1;
    nbl_grpc_rx_init(&s->rx, MAX_GRPC_MSG);

    nbl_h2p_hdr_t hdrs[8];
    size_t n = 0;
    hdrs[n++] = (nbl_h2p_hdr_t){":method", "POST"};
    hdrs[n++] = (nbl_h2p_hdr_t){":scheme", "https"};
    hdrs[n++] = (nbl_h2p_hdr_t){":path", path};
    hdrs[n++] = (nbl_h2p_hdr_t){":authority", h->authority};
    hdrs[n++] = (nbl_h2p_hdr_t){"content-type", "application/grpc"};
    hdrs[n++] = (nbl_h2p_hdr_t){"te", "trailers"};
    hdrs[n++] = (nbl_h2p_hdr_t){"user-agent", "netbird-lite/" NETBIRD_LITE_VERSION};
    if (xn && xv) {
        hdrs[n++] = (nbl_h2p_hdr_t){xn, xv};
    }
    int rc = nbl_h2p_open_stream(&h->proto, hdrs, n, true, &s->id);
    if (rc < 0 && flush_out(h) == 0) { /* the send queue may just be full */
        rc = nbl_h2p_open_stream(&h->proto, hdrs, n, true, &s->id);
    }
    if (rc < 0) {
        s->used = false;
        return NULL;
    }
    return s;
}

int nbl_h2_send(nbl_stream_t *s, const uint8_t *msg, size_t len, bool last)
{
    if (!s || !s->used) {
        return -1;
    }
    nbl_h2p_t *p = &s->h->proto;
    if (!msg) { /* no message: half-close only */
        return last && nbl_h2p_send_data(p, s->id, NULL, 0, true) < 0 ? -1 : 0;
    }
    if (len > MAX_GRPC_MSG) {
        return -1;
    }
    uint8_t *f = malloc(5 + len);
    if (!f) {
        return -1;
    }
    int fl = nbl_grpc_frame(f, 5 + len, msg, len);
    int rc = nbl_h2p_send_data(p, s->id, f, (size_t)fl, last); /* copied; sent as the windows allow */
    free(f);
    return rc < 0 ? -1 : 0;
}

void nbl_h2_set_deadline(nbl_stream_t *s, int timeout_ms)
{
    if (s && s->used) {
        s->deadline_us = timeout_ms > 0 ? esp_timer_get_time() + (int64_t)timeout_ms * 1000 : 0;
    }
}

/* Calls past their deadline are cancelled and reported through on_close. */
static void expire_calls(nbl_h2_t *h, int64_t now)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        nbl_stream_t *s = &h->streams[i];
        if (s->used && s->deadline_us && now > s->deadline_us) {
            ESP_LOGW(TAG, "stream %u: deadline exceeded", (unsigned)s->id);
            nbl_h2p_reset(&h->proto, s->id);
            close_stream(s, 4, "deadline exceeded", 0);
        }
    }
}

int nbl_h2_run(nbl_h2_t *h, int timeout_ms)
{
    if (h->dead) {
        return -1;
    }
    int64_t now = esp_timer_get_time();
    if (now - h->last_rx_us > DEAD_AFTER_US) {
        ESP_LOGW(TAG, "no data for %d s", (int)((now - h->last_rx_us) / 1000000));
        h->dead = true;
        return -1;
    }
    if (flush_out(h) < 0) { /* empties the send queue */
        return -1;
    }
    expire_calls(h, now);
    if (now - h->last_ping_us > PING_EVERY_US && nbl_h2p_ping(&h->proto) == 0) {
        h->last_ping_us = now;
    }
    if (flush_out(h) < 0) {
        return -1;
    }
    /* receive */
    if (esp_tls_get_bytes_avail(h->tls) <= 0) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(h->fd, &rf);
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        int r = select(h->fd + 1, &rf, NULL, NULL, &tv);
        if (r < 0) {
            h->dead = true;
            return -1;
        }
        if (r == 0) {
            return 0;
        }
    }
    uint8_t buf[2048];
    for (int i = 0; i < 8; i++) {
        int n = esp_tls_conn_read(h->tls, (char *)buf, sizeof(buf));
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            break;
        }
        if (n <= 0) {
            ESP_LOGW(TAG, "read error/EOF: %d", n);
            h->dead = true;
            return -1;
        }
        h->last_rx_us = esp_timer_get_time();
        for (int off = 0; off < n;) {
            int used = nbl_h2p_input(&h->proto, buf + off, (size_t)(n - off));
            if (used < 0) {
                h->dead = true;
                return -1;
            }
            off += used;
            if (off < n && flush_out(h) < 0) { /* send queue full: send, then go on */
                return -1;
            }
        }
        if (esp_tls_get_bytes_avail(h->tls) <= 0) {
            break;
        }
    }
    /* answers (PING/SETTINGS ACK, WINDOW_UPDATE) go out now, not with the next run: the
       server's keepalive expects the PING ACK within 2 s */
    if (flush_out(h) < 0) {
        return -1;
    }
    return h->dead ? -1 : 0;
}

/* ---------------- unary call ---------------- */

struct unary {
    uint8_t *resp;
    size_t rlen;
    int status;
    char msg[96];
    bool done;
};

static void un_msg(void *ctx, const uint8_t *m, size_t len)
{
    struct unary *u = ctx;
    free(u->resp);
    u->resp = malloc(len ? len : 1);
    u->rlen = 0;
    if (u->resp) {
        memcpy(u->resp, m, len);
        u->rlen = len;
    }
}

static void un_close(void *ctx, int st, const char *gm, uint32_t err)
{
    struct unary *u = ctx;
    u->status = st;
    if (st < 0 && err) {
        u->status = 100 + (int)err;
    }
    strlcpy(u->msg, gm ? gm : "", sizeof(u->msg));
    u->done = true;
}

int nbl_h2_unary(nbl_h2_t *h, const char *path, const uint8_t *req, size_t req_len, uint8_t **resp,
                 size_t *resp_len, int *grpc_status, char *grpc_message, size_t msg_cap, int timeout_ms)
{
    struct unary u = {.status = -1};
    nbl_stream_cb_t cb = {.on_msg = un_msg, .on_close = un_close};
    nbl_stream_t *s = nbl_h2_call(h, path, NULL, NULL, &cb, &u);
    if (!s) {
        return -1;
    }
    if (nbl_h2_send(s, req ? req : (const uint8_t *)"", req_len, true) < 0) {
        drop_call(h, s);
        return -1;
    }
    int64_t end = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (!u.done && esp_timer_get_time() < end) {
        if (nbl_h2_run(h, 100) < 0) {
            break;
        }
    }
    if (!u.done) {
        drop_call(h, s); /* a reset fires no close callback: free the call slot here */
        free(u.resp);
        return -2;
    }
    if (grpc_status) {
        *grpc_status = u.status;
    }
    if (grpc_message && msg_cap) {
        strlcpy(grpc_message, u.msg, msg_cap);
    }
    *resp = u.resp;
    *resp_len = u.rlen;
    return u.status == 0 ? 0 : -3;
}
