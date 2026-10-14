// SPDX-License-Identifier: MIT
#include "nbl_h2.h"
#include "netbird_lite.h"
#include "nbl_grpc.h"

#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ssl.h"
#include "nghttp2/nghttp2.h"

#ifndef CONFIG_MBEDTLS_SSL_ALPN
#error "netbird-lite needs CONFIG_MBEDTLS_SSL_ALPN: HTTP/2 is negotiated via ALPN"
#endif

static const char *TAG = "nbl_h2";

#define MAX_STREAMS 8
#define MAX_GRPC_MSG (48 * 1024)
#define PING_EVERY_US (20LL * 1000000) /* keep >= 15 s, see nbl_h2_lite.c */
#define DEAD_AFTER_US (70LL * 1000000)

struct txbuf {
    struct txbuf *next;
    size_t len, off;
    uint8_t data[];
};

struct nbl_stream {
    nbl_h2_t *h;
    int32_t id;
    bool used;
    nbl_stream_cb_t cb;
    void *ctx;
    struct txbuf *txh, *txt;
    bool tx_end;
    bool broken;         /* gRPC framing error: reset, closing */
    int64_t deadline_us; /* 0 = none */
    nbl_grpc_rx_t rx;
    int grpc_status;
    char grpc_msg[96];
};

struct nbl_h2 {
    esp_tls_t *tls;
    int fd;
    nghttp2_session *sess;
    nbl_stream_t streams[MAX_STREAMS];
    bool dead;
    char authority[160];
    int64_t last_ping_us, last_rx_us;
};

static void stream_release(nbl_stream_t *s)
{
    while (s->txh) {
        struct txbuf *n = s->txh->next;
        free(s->txh);
        s->txh = n;
    }
    s->txt = NULL;
    nbl_grpc_rx_free(&s->rx);
    memset(s, 0, sizeof(*s));
}

static nbl_stream_t *stream_by_id(nbl_h2_t *h, int32_t id)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (h->streams[i].used && h->streams[i].id == id) {
            return &h->streams[i];
        }
    }
    return NULL;
}

/* ---------------- nghttp2 callbacks ---------------- */

static ssize_t cb_send(nghttp2_session *sess, const uint8_t *data, size_t length, int flags, void *ud)
{
    (void)sess;
    (void)flags;
    nbl_h2_t *h = ud;
    size_t off = 0;
    while (off < length) {
        int n = esp_tls_conn_write(h->tls, (const char *)data + off, length - off);
        if (n > 0) {
            off += (size_t)n;
        } else if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(1);
        } else {
            h->dead = true;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return (ssize_t)length;
}

static int cb_header(nghttp2_session *sess, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen, uint8_t flags, void *ud)
{
    (void)flags;
    nbl_h2_t *h = ud;
    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    nbl_stream_t *s = stream_by_id(h, frame->hd.stream_id);
    (void)sess;
    if (!s || s->broken) {
        return 0;
    }
    char n[64], v[200];
    size_t nl = namelen < sizeof(n) - 1 ? namelen : sizeof(n) - 1;
    size_t vl = valuelen < sizeof(v) - 1 ? valuelen : sizeof(v) - 1;
    memcpy(n, name, nl);
    n[nl] = 0;
    memcpy(v, value, vl);
    v[vl] = 0;
    if (!strcmp(n, "grpc-status")) {
        s->grpc_status = atoi(v);
    } else if (!strcmp(n, "grpc-message")) {
        strlcpy(s->grpc_msg, v, sizeof(s->grpc_msg));
    }
    if (s->cb.on_header) {
        s->cb.on_header(s->ctx, n, v);
    }
    return 0;
}

static void grpc_msg(void *ctx, const uint8_t *m, size_t len)
{
    nbl_stream_t *s = ctx;
    if (s->cb.on_msg) {
        s->cb.on_msg(s->ctx, m, len);
    }
}

static int cb_data(nghttp2_session *sess, uint8_t flags, int32_t id, const uint8_t *data, size_t len, void *ud)
{
    (void)flags;
    nbl_stream_t *s = stream_by_id(ud, id);
    if (!s || s->broken) {
        return 0;
    }
    if (nbl_grpc_rx_feed(&s->rx, grpc_msg, s, data, len) < 0) {
        /* reset only this stream; cb_close reports it */
        ESP_LOGW(TAG, "broken gRPC framing, dropping stream %d", (int)id);
        s->broken = true;
        s->grpc_status = -1;
        strlcpy(s->grpc_msg, "grpc framing", sizeof(s->grpc_msg));
        if (nghttp2_submit_rst_stream(sess, NGHTTP2_FLAG_NONE, id, NGHTTP2_CANCEL) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

#ifdef NBL_H2_TRACE
static int cb_frame_send(nghttp2_session *sess, const nghttp2_frame *f, void *ud)
{
    (void)sess;
    (void)ud;
    ESP_LOGI(TAG, "h2 >> type=%u stream=%d len=%u flags=%02x", f->hd.type, (int)f->hd.stream_id, (unsigned)f->hd.length, f->hd.flags);
    return 0;
}

static int cb_frame_recv(nghttp2_session *sess, const nghttp2_frame *f, void *ud)
{
    (void)sess;
    (void)ud;
    ESP_LOGI(TAG, "h2 << type=%u stream=%d len=%u flags=%02x", f->hd.type, (int)f->hd.stream_id, (unsigned)f->hd.length, f->hd.flags);
    return 0;
}
#endif

static int cb_close(nghttp2_session *sess, int32_t id, uint32_t err, void *ud)
{
    (void)sess;
    nbl_stream_t *s = stream_by_id(ud, id);
    if (!s) {
        return 0;
    }
    if (s->cb.on_close) {
        s->cb.on_close(s->ctx, s->grpc_status, s->grpc_msg, s->broken ? 0 : err);
    }
    stream_release(s);
    return 0;
}

static ssize_t cb_tx_read(nghttp2_session *sess, int32_t id, uint8_t *buf, size_t length, uint32_t *flags,
                          nghttp2_data_source *src, void *ud)
{
    (void)sess;
    (void)id;
    (void)ud;
    nbl_stream_t *s = src->ptr;
    size_t copied = 0;
    while (s->txh && copied < length) {
        struct txbuf *b = s->txh;
        size_t n = b->len - b->off;
        if (n > length - copied) {
            n = length - copied;
        }
        memcpy(buf + copied, b->data + b->off, n);
        b->off += n;
        copied += n;
        if (b->off == b->len) {
            s->txh = b->next;
            if (!s->txh) {
                s->txt = NULL;
            }
            free(b);
        }
    }
    if (copied == 0) {
        if (s->tx_end) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED;
    }
    if (!s->txh && s->tx_end) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)copied;
}

/* ---------------- connection ---------------- */

static bool alpn_is_h2(esp_tls_t *tls)
{
    const mbedtls_ssl_context *ssl = esp_tls_get_ssl_context(tls);
    const char *p = ssl ? mbedtls_ssl_get_alpn_protocol(ssl) : NULL;
    return p && !strcmp(p, "h2");
}

static int flush(nbl_h2_t *h)
{
    while (nghttp2_session_want_write(h->sess)) {
        int rv = nghttp2_session_send(h->sess);
        if (rv != 0 || h->dead) {
            h->dead = true;
            return -1;
        }
    }
    return 0;
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
    if (!ok) {
        if (h->tls) {
            esp_tls_conn_destroy(h->tls);
        }
        free(h);
        return NULL;
    }
    esp_tls_get_conn_sockfd(h->tls, &h->fd);
    snprintf(h->authority, sizeof(h->authority), "%s:%d", host, port);

    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, cb_send);
    nghttp2_session_callbacks_set_on_header_callback(cbs, cb_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, cb_close);
#ifdef NBL_H2_TRACE
    nghttp2_session_callbacks_set_on_frame_send_callback(cbs, cb_frame_send);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, cb_frame_recv);
#endif
    int rv = nghttp2_session_client_new(&h->sess, cbs, h);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) {
        esp_tls_conn_destroy(h->tls);
        free(h);
        return NULL;
    }
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
    };
    nghttp2_submit_settings(h->sess, NGHTTP2_FLAG_NONE, iv, 2);
    h->last_rx_us = h->last_ping_us = esp_timer_get_time();
    if (flush(h) < 0) {
        nbl_h2_free(h);
        return NULL;
    }
    return h;
}

void nbl_h2_free(nbl_h2_t *h)
{
    if (!h) {
        return;
    }
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (h->streams[i].used) {
            stream_release(&h->streams[i]);
        }
    }
    if (h->sess) {
        nghttp2_session_del(h->sess);
    }
    if (h->tls) {
        esp_tls_conn_destroy(h->tls);
    }
    free(h);
}

bool nbl_h2_alive(const nbl_h2_t *h)
{
    return h && !h->dead;
}

#define NV(n, v) {(uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, NGHTTP2_NV_FLAG_NONE}

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

    nghttp2_nv nva[8];
    size_t n = 0;
    nghttp2_nv m = NV(":method", "POST"), sc = NV(":scheme", "https"), ct = NV("content-type", "application/grpc"),
               te = NV("te", "trailers"), ua = NV("user-agent", "netbird-lite/" NETBIRD_LITE_VERSION);
    nva[n++] = m;
    nva[n++] = sc;
    nva[n++] = (nghttp2_nv){(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), NGHTTP2_NV_FLAG_NONE};
    nva[n++] = (nghttp2_nv){(uint8_t *)":authority", (uint8_t *)h->authority, 10, strlen(h->authority),
                            NGHTTP2_NV_FLAG_NONE};
    nva[n++] = ct;
    nva[n++] = te;
    nva[n++] = ua;
    if (xn && xv) {
        nva[n++] = (nghttp2_nv){(uint8_t *)xn, (uint8_t *)xv, strlen(xn), strlen(xv), NGHTTP2_NV_FLAG_NONE};
    }
    nghttp2_data_provider prd = {.source = {.ptr = s}, .read_callback = cb_tx_read};
    int32_t id = nghttp2_submit_request(h->sess, NULL, nva, n, &prd, NULL);
    if (id < 0) {
        ESP_LOGE(TAG, "submit_request: %s", nghttp2_strerror(id));
        s->used = false;
        return NULL;
    }
    s->id = id;
    return s;
}

int nbl_h2_send(nbl_stream_t *s, const uint8_t *msg, size_t len, bool last)
{
    if (!s || !s->used || len > MAX_GRPC_MSG) {
        return -1;
    }
    if (msg) {
        struct txbuf *b = malloc(sizeof(*b) + 5 + len);
        if (!b) {
            return -1;
        }
        b->next = NULL;
        b->off = 0;
        b->len = 5 + len;
        b->data[0] = 0;
        b->data[1] = (uint8_t)(len >> 24);
        b->data[2] = (uint8_t)(len >> 16);
        b->data[3] = (uint8_t)(len >> 8);
        b->data[4] = (uint8_t)len;
        memcpy(b->data + 5, msg, len);
        if (s->txt) {
            s->txt->next = b;
        } else {
            s->txh = b;
        }
        s->txt = b;
    }
    if (last) {
        s->tx_end = true;
    }
    nghttp2_session_resume_data(s->h->sess, s->id);
    return 0;
}

/* Detaches a call from its callbacks and cancels it; the slot is released by cb_close once
   the reset is through (nghttp2 may still read the request body from it until then). */
static void detach_call(nbl_h2_t *h, nbl_stream_t *s)
{
    memset(&s->cb, 0, sizeof(s->cb));
    s->deadline_us = 0;
    nghttp2_submit_rst_stream(h->sess, NGHTTP2_FLAG_NONE, s->id, NGHTTP2_CANCEL);
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
            ESP_LOGW(TAG, "stream %d: deadline exceeded", (int)s->id);
            nbl_stream_cb_t cb = s->cb;
            detach_call(h, s);
            if (cb.on_close) {
                cb.on_close(s->ctx, 4, "deadline exceeded", 0);
            }
        }
    }
}

int nbl_h2_run(nbl_h2_t *h, int timeout_ms)
{
    if (h->dead) {
        return -1;
    }
    int64_t now = esp_timer_get_time();
    if (now - h->last_ping_us > PING_EVERY_US) {
        nghttp2_submit_ping(h->sess, NGHTTP2_FLAG_NONE, NULL);
        h->last_ping_us = now;
    }
    if (now - h->last_rx_us > DEAD_AFTER_US) {
        ESP_LOGW(TAG, "no data for %d s, connection considered dead", (int)((now - h->last_rx_us) / 1000000));
        h->dead = true;
        return -1;
    }
    expire_calls(h, now);
    if (flush(h) < 0) {
        return -1;
    }
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
    uint8_t buf[1536];
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
        ssize_t rv = nghttp2_session_mem_recv(h->sess, buf, (size_t)n);
        if (rv < 0 || h->dead) {
            ESP_LOGW(TAG, "mem_recv: %s", nghttp2_strerror((int)rv));
            h->dead = true;
            return -1;
        }
        if (esp_tls_get_bytes_avail(h->tls) <= 0) {
            break;
        }
    }
    return flush(h);
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
        u->status = 100 + (int)err; /* report HTTP/2 errors distinctly */
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
        detach_call(h, s);
        return -1;
    }
    int64_t end = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (!u.done && esp_timer_get_time() < end) {
        if (nbl_h2_run(h, 100) < 0) {
            break;
        }
    }
    if (!u.done) {
        detach_call(h, s); /* otherwise ctx would later point into a dead stack frame */
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
