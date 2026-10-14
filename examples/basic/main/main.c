// netbird-lite example: joins a NetBird network and serves HTTP over the overlay.
//
//   GET  /            short greeting with the NetBird address
//   GET  /status      JSON with the client status, counters, heap and stack reserves
//   POST /echo        echoes the request body (up to 1 KB)
//   GET  /blob?n=N    N bytes of a fixed pattern (i % 251), for throughput and integrity tests
//   GET  /fetch?ip=A.B.C.D&port=N
//                     the device itself opens a TCP connection, sends "GET / HTTP/1.0" and reports
//                     the status line (shows that replies to outgoing connections pass the firewall)
//   TCP  8081         echo server that the test policy deliberately does NOT allow
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "netbird_lite.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

static const char *TAG = "example";

/* Smallest free stack of a task since it started (bytes), 0 if the task does not exist. */
static unsigned stack_reserve(const char *task_name)
{
    TaskHandle_t t = xTaskGetHandle(task_name);
    return t ? (unsigned)uxTaskGetStackHighWaterMark(t) : 0;
}

static esp_err_t root_get(httpd_req_t *req)
{
    nbl_status_t st;
    nbl_get_status(&st);
    char buf[160];
    snprintf(buf, sizeof(buf), "hello from ESP32 over NetBird (%s), free heap: %u bytes\n", st.ip, (unsigned)esp_get_free_heap_size());
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_get(httpd_req_t *req)
{
    nbl_status_t st;
    nbl_get_status(&st);
    char buf[640];
    snprintf(buf, sizeof(buf),
             "{\"state\":%d,\"ip\":\"%s\",\"pubkey\":\"%s\",\"signal\":%d,\"relay\":%d,\"peers\":%d,\"peers_up\":%d,"
             "\"rules\":%d,\"relay_rx\":%u,\"relay_tx\":%u,\"relay_dropped\":%u,\"relay_reconnects\":%u,"
             "\"acl_pass\":%u,\"acl_drop\":%u,\"heap\":%u,\"heap_min\":%u,\"heap_largest\":%u,"
             "\"stack_ctrl\":%u,\"stack_relay\":%u,\"stack_tcpip\":%u,\"stack_main\":%u}\n",
             st.state, st.ip, st.pubkey, st.signal_up, st.relay_up, st.peers, st.peers_up, st.acl_rules,
             (unsigned)st.relay_rx, (unsigned)st.relay_tx, (unsigned)st.relay_dropped, (unsigned)st.relay_reconnects,
             (unsigned)st.acl_pass, (unsigned)st.acl_drop, (unsigned)esp_get_free_heap_size(),
             (unsigned)esp_get_minimum_free_heap_size(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
             stack_reserve("nbl_ctrl"), stack_reserve("nbl_relay"), stack_reserve("tiT"), stack_reserve("main"));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t echo_post(httpd_req_t *req)
{
    char buf[1024];
    if (req->content_len > sizeof(buf)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body too large (max 1024 bytes)");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int n = httpd_req_recv(req, buf + got, req->content_len - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (n <= 0) {
            return ESP_FAIL;
        }
        got += (size_t)n;
    }
    return httpd_resp_send(req, buf, (ssize_t)got);
}

static esp_err_t blob_get(httpd_req_t *req)
{
    char q[32] = "";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    char v[16] = "";
    httpd_query_key_value(q, "n", v, sizeof(v));
    long n = atol(v);
    if (n < 0 || n > 4 * 1024 * 1024) {
        n = 0;
    }
    httpd_resp_set_type(req, "application/octet-stream");
    char chunk[512];
    for (long off = 0; off < n;) {
        size_t m = (size_t)(n - off) < sizeof(chunk) ? (size_t)(n - off) : sizeof(chunk);
        for (size_t i = 0; i < m; i++) {
            chunk[i] = (char)((off + (long)i) % 251);
        }
        if (httpd_resp_send_chunk(req, chunk, m) != ESP_OK) {
            return ESP_FAIL;
        }
        off += (long)m;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t fetch_get(httpd_req_t *req)
{
    char q[64] = "", ip[16] = "", port[8] = "";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    httpd_query_key_value(q, "ip", ip, sizeof(ip));
    httpd_query_key_value(q, "port", port, sizeof(port));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(port))};
    if (!inet_aton(ip, &a.sin_addr) || a.sin_port == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "usage: /fetch?ip=A.B.C.D&port=N");
    }
    char res[160];
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    struct timeval tv = {.tv_sec = 5};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    /* non-blocking connect with a 5 s limit (a blocking one waits for all SYN retries) */
    int connected = -1;
    if (s >= 0) {
        int fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
        if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0 || errno == EINPROGRESS) {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            int err = 0;
            socklen_t el = sizeof(err);
            if (select(s + 1, NULL, &wf, NULL, &tv) == 1 && getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) == 0) {
                connected = err == 0 ? 0 : -1;
                errno = err;
            } else {
                errno = ETIMEDOUT;
            }
        }
        fcntl(s, F_SETFL, fl);
    }
    if (connected != 0) {
        snprintf(res, sizeof(res), "{\"ok\":false,\"error\":\"connect failed (errno %d)\"}\n", errno);
    } else {
        static const char rq[] = "GET / HTTP/1.0\r\n\r\n";
        char buf[256];
        int total = 0, n;
        send(s, rq, sizeof(rq) - 1, 0);
        int first = recv(s, buf, sizeof(buf) - 1, 0);
        if (first > 0) {
            total = first;
            while ((n = recv(s, buf + 64, sizeof(buf) - 65, 0)) > 0) { /* keep the first line in buf */
                total += n;
            }
            buf[first < 64 ? first : 64] = 0;
            char *eol = strpbrk(buf, "\r\n");
            if (eol) {
                *eol = 0;
            }
            snprintf(res, sizeof(res), "{\"ok\":true,\"bytes\":%d,\"status\":\"%.60s\"}\n", total, buf);
        } else {
            snprintf(res, sizeof(res), "{\"ok\":false,\"error\":\"no response (errno %d)\"}\n", errno);
        }
    }
    if (s >= 0) {
        close(s);
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, res, HTTPD_RESP_USE_STRLEN);
}

/* TCP echo on port 8081: deliberately NOT allowed by the test policy, so the firewall must block it */
static void echo8081_task(void *arg)
{
    (void)arg;
    int ls = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(8081), .sin_addr.s_addr = htonl(INADDR_ANY)};
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 2) != 0) {
        ESP_LOGE(TAG, "echo8081: bind/listen failed");
        vTaskDelete(NULL);
    }
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) {
            continue;
        }
        char buf[128];
        int n;
        while ((n = recv(c, buf, sizeof(buf), 0)) > 0) {
            send(c, buf, n, 0);
        }
        close(c);
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());
#if CONFIG_EXAMPLE_CONNECT_WIFI && CONFIG_EXAMPLE_WIFI_PS_NONE
    /* Wi-Fi modem sleep adds up to one beacon interval (~100 ms) of latency per received packet. */
    esp_wifi_set_ps(WIFI_PS_NONE);
#endif

    httpd_config_t hc = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &hc) == ESP_OK) {
        const httpd_uri_t uris[] = {
            {.uri = "/", .method = HTTP_GET, .handler = root_get},
            {.uri = "/status", .method = HTTP_GET, .handler = status_get},
            {.uri = "/echo", .method = HTTP_POST, .handler = echo_post},
            {.uri = "/blob", .method = HTTP_GET, .handler = blob_get},
            {.uri = "/fetch", .method = HTTP_GET, .handler = fetch_get},
        };
        for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
            httpd_register_uri_handler(srv, &uris[i]);
        }
    }

    xTaskCreate(echo8081_task, "echo8081", 3072, NULL, 4, NULL);

    ESP_LOGI(TAG, "free heap before netbird-lite: %u bytes", (unsigned)esp_get_free_heap_size());
    nbl_config_t cfg = {
        .management_url = CONFIG_EXAMPLE_NB_MGMT_URL,
        .setup_key = CONFIG_EXAMPLE_NB_SETUP_KEY[0] ? CONFIG_EXAMPLE_NB_SETUP_KEY : NULL,
        .hostname = CONFIG_EXAMPLE_NB_HOSTNAME[0] ? CONFIG_EXAMPLE_NB_HOSTNAME : NULL,
    };
    esp_err_t err = nbl_start(&cfg);
    if (err != ESP_OK) {
        /* No reboot loop: e.g. an unregistered device without a setup key stays reachable on the LAN. */
        ESP_LOGE(TAG, "nbl_start failed: %s", esp_err_to_name(err));
    }

    for (;;) {
        nbl_status_t st;
        nbl_get_status(&st);
        ESP_LOGI(TAG, "state=%d ip=%s signal=%d relay=%d peers=%d/%d rx=%u tx=%u acl=%u/%u heap=%u min=%u err='%s'", st.state,
                 st.ip, st.signal_up, st.relay_up, st.peers_up, st.peers, (unsigned)st.relay_rx, (unsigned)st.relay_tx,
                 (unsigned)st.acl_pass, (unsigned)st.acl_drop, (unsigned)esp_get_free_heap_size(),
                 (unsigned)esp_get_minimum_free_heap_size(), st.last_error);
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
