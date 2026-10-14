// SPDX-License-Identifier: Apache-2.0
// Control plane: management (login/sync), signal (offer/answer), peer table, wiring to relay and WireGuard.
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "esp_chip_info.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "netbird_lite.h"
#include "nbl_crypto.h"
#include "nbl_h2.h"
#include "nbl_netmap.h"
#include "nbl_relay.h"
#include "nbl_wg.h"
#include "nbl_wire.h"
#include "nbl_mgmt.pb.h"
#include "nbl_signal.pb.h"
#include "nvs.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "sdkconfig.h"

static const char *TAG = "nbl";

/* NetBird version we report: PeerSystemMeta.netbirdVersion (remote peers see it as
 * RemotePeerConfig.agentVersion) and Body.netBirdVersion in signal messages (only logged there).
 * The netbird-lite release travels as SemVer build metadata, which every upstream parser ignores
 * when comparing (hashicorp/go-version, x/mod/semver; version.MeetsMinVersion and
 * lazyconn.normalizeVersion cut at the first '-' and still parse "0.44.0+netbird"). A pre-release
 * suffix such as "0.1.0-nbl" would fail every ">= x" constraint of hashicorp/go-version.
 * Version gates of NetBird v0.80.0 that read it:
 *
 *   gate (upstream source)                                       needs          with 0.44.0+...
 *   skip the deprecated SyncResponse.remotePeers duplicate       >= 0.29.3      skipped (smaller sync)
 *     (management/internals/shared/grpc/conversion.go)
 *   remote peers use lazy connections towards us                >= 0.45.0      no: permanent connection
 *     (client/internal/lazyconn/support.go via conn_mgr.go;                     (we implement neither
 *     normalizeVersion strips v/a and everything after '-')                     lazy conns nor GO_IDLE)
 *   port ranges in firewall rules                                >= 0.48.0      no: the server sends
 *     (shared/management/types/firewall_helpers.go, legacynmap)                 single ports only and
 *                                                                               DROPS ranges (start !=
 *                                                                               end) for this peer
 *   DNS forwarder port 22054 for the whole account               all >= 0.59.0  account stays on 5353
 *     (network_map/controller/controller.go, x/mod/semver)                      (compatibility path)
 *   native SSH companion rule 22022 (firewall_helpers.go)        >= 0.60.0      no (no SSH server)
 *   remote jobs (management/server/peer.go)                      >= 0.64.0      rejected (not supported)
 *   posture check "NetBird version" (admin-configured)           >= minimum     passes up to 0.44.0
 *
 * "development", "dev-" and "ci-" versions pass every gate, so they must not be used. Re-check
 * this table when upstream adds gates (grep NewConstraint, MeetsMinVersion, semver.Compare). */
#define NBL_LITE_VERSION NETBIRD_LITE_VERSION
#define NBL_VERSION "0.44.0+netbird-lite." NBL_LITE_VERSION

#define MAX_PEERS CONFIG_NBL_MAX_PEERS
#define OFFER_EVERY_US (15LL * 1000000)
#define PATH_MGMT "/management.ManagementService/"
#define PATH_SIGNAL "/signalexchange.SignalExchange/ConnectStream" /* receive only: the server never reads from it */
#define PATH_SIGNAL_SEND "/signalexchange.SignalExchange/Send"   /* sending = one unary call per message */

#define RETRY_MIN_S 2      /* management reconnect: 2..30 s, +-50 % jitter, reset once synced */
#define RETRY_MAX_S 30
#define FATAL_RETRY_S 300  /* login rejected (invalid setup key, peer not registered): every 5 min */
#define SIG_RETRY_MIN_S 1  /* signal reconnect: 1..30 s, +-50 % jitter */
#define SIG_RETRY_MAX_S 30
#define SIG_STABLE_US (60LL * 1000000)       /* a registered stream up this long resets the backoff */
#define SIG_REGISTER_US (10LL * 1000000)     /* time for the x-wiretrustee-peer-registered header */
#define SIG_OPEN_STACK 6144                  /* TLS handshake only (relay task: 3.5 KB peak) */
#define RELAY_ADDR_CAP NBL_NM_RELAY_URL_CAP  /* relay URLs incl. NUL, as nbl_relay stores them */
#define HOST_CAP 96

#define GRPC_PERMISSION_DENIED 7
#define GRPC_NOT_FOUND 5

typedef struct {
    bool used;
    char key[NBL_KEY_B64 + 1];
    uint8_t pub[32];
    uint8_t shared[32];
    uint8_t relay_id[NBL_RELAY_ID_LEN];
    int wg_slot;
    uint32_t ip4;
    bool remote_known;   /* offer or answer received from the remote peer */
    bool need_answer;    /* offer received: answered from the session loop once our relay is up */
    char remote_relay[RELAY_ADDR_CAP];
    bool wg_requested;
    bool up;
    int64_t last_offer_us;
    int offers;
} peer_t;

/* Signal connection, driven by sig_service() from the session loop. Callbacks only record
 * events; nothing blocks while the management connection has to answer keepalive pings. */
typedef enum {
    SIG_IDLE,        /* no signal server known yet */
    SIG_WAIT,        /* backoff until sig_next_us */
    SIG_OPENING,     /* helper task runs the TLS handshake (dedicated connection) */
    SIG_REGISTERING, /* ConnectStream open, waiting for x-wiretrustee-peer-registered */
    SIG_UP,
} sig_state_t;

static struct {
    char mgmt_url[128], setup_key[64], hostname[40];
    uint8_t priv[32], pub[32];
    char pub_b64[NBL_KEY_B64 + 1];
    bool registered;
    uint8_t srv_shared[32];

    nbl_h2_t *mgmt;
    nbl_stream_t *sync_s;
    bool sync_closed;
    bool restart;        /* end the session (reconnect with backoff), e.g. after a failed netif update */
    bool synced;         /* this session applied a network map */
    bool have_serial;
    uint64_t serial;     /* Serial of the last applied network map (this session) */
    char mgmt_host[HOST_CAP];
    int mgmt_port;

    sig_state_t sig_state;
    char sig_host[HOST_CAP]; /* wanted signal server, "" = none yet */
    int sig_port;
    nbl_h2_t *sig;           /* == mgmt when signal runs on the management server */
    bool sig_registered, sig_closed;
    int64_t sig_next_us, sig_deadline_us, sig_up_us;
    int sig_backoff_s;
    QueueHandle_t sig_q;     /* helper task -> control task: the opened connection or NULL */
    bool sig_inflight;
    char sig_open_host[HOST_CAP];
    int sig_open_port;

    peer_t peers[MAX_PEERS];
    uint32_t my_ip;
    uint8_t my_prefix;
    bool ip_set;
    nbl_acl_rule_t *acl_pending; /* a rule set nbl_acl_set() refused, retried by tick() */
    int acl_pending_n;

    TaskHandle_t task;
    volatile bool stop;
    nbl_status_t st;     /* working copy, written by the control task only */
    int64_t last_tick_us;
} C;

/* Published status: nbl_get_status() copies it under the mutex. Outside of C: nbl_start() clears C. */
static SemaphoreHandle_t s_st_mu;
static nbl_status_t s_st_pub;
static bool s_started;

/* ============================== Helpers ============================== */

static void st_publish(void)
{
    xSemaphoreTake(s_st_mu, portMAX_DELAY);
    s_st_pub = C.st;
    xSemaphoreGive(s_st_mu);
}

static void set_state(nbl_state_t s)
{
    C.st.state = s;
    st_publish();
}

static void set_err(const char *fmt, const char *a)
{
    snprintf(C.st.last_error, sizeof(C.st.last_error), fmt, a ? a : "");
    ESP_LOGW(TAG, "%s", C.st.last_error);
    st_publish();
}

/* s seconds +-50 %, in milliseconds */
static uint32_t jitter_ms(int s)
{
    uint32_t ms = (uint32_t)s * 1000;
    return ms / 2 + esp_random() % (ms + 1);
}

static int backoff_next(int s, int max)
{
    return s * 2 > max ? max : s * 2;
}

static peer_t *peer_by_key(const char *k)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (C.peers[i].used && !strcmp(C.peers[i].key, k)) {
            return &C.peers[i];
        }
    }
    return NULL;
}

/* "https://host[:port][/...]" or "host[:port]" (the form HostConfig.uri uses) */
static int parse_url(const char *url, char *host, size_t hcap, int *port)
{
    const char *p = url;
    *port = 443;
    if (!strncmp(p, "https://", 8)) {
        p += 8;
    } else if (strstr(p, "://")) {
        return -1; /* h2c (cleartext HTTP/2) and other schemes are not supported */
    }
    const char *colon = strchr(p, ':');
    size_t hl = colon ? (size_t)(colon - p) : strcspn(p, "/");
    if (hl == 0 || hl >= hcap) {
        return -1;
    }
    memcpy(host, p, hl);
    host[hl] = 0;
    if (colon) {
        char *end;
        long v = strtol(colon + 1, &end, 10);
        if (end == colon + 1 || (*end && *end != '/') || v < 1 || v > 65535) {
            return -1;
        }
        *port = (int)v;
    }
    return 0;
}

/* ============================== Management ============================== */

static void fill_meta(management_PeerSystemMeta *m)
{
    memset(m, 0, sizeof(*m));
    strlcpy(m->hostname, C.hostname, sizeof(m->hostname));
    strlcpy(m->goOS, "freertos", sizeof(m->goOS));
    strlcpy(m->kernel, "esp-idf", sizeof(m->kernel));
    strlcpy(m->core, esp_get_idf_version(), sizeof(m->core));
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    const char *chip = ci.model == CHIP_ESP32S3 ? "esp32s3"
                       : ci.model == CHIP_ESP32C6 ? "esp32c6"
                       : ci.model == CHIP_ESP32   ? "esp32"
                                                  : "esp32x";
    strlcpy(m->platform, chip, sizeof(m->platform));
    strlcpy(m->OS, "FreeRTOS", sizeof(m->OS));
    strlcpy(m->netbirdVersion, NBL_VERSION, sizeof(m->netbirdVersion));
    strlcpy(m->kernelVersion, esp_get_idf_version(), sizeof(m->kernelVersion));
    strlcpy(m->OSVersion, esp_get_idf_version(), sizeof(m->OSVersion));
}

/* Encrypted management envelope (EncryptedMessage): wgPubKey=1, body=2 */
static uint8_t *mgmt_envelope(const uint8_t *plain, size_t plen, size_t *out_len)
{
    uint8_t *sealed = malloc(plen + 40);
    uint8_t *env = malloc(plen + 40 + 64);
    if (!sealed || !env || nbl_box_seal(sealed, C.srv_shared, plain, plen) < 0) {
        free(sealed);
        free(env);
        return NULL;
    }
    size_t o = nbl_put_bytes(env, 0, 1, C.pub_b64, strlen(C.pub_b64));
    o = nbl_put_bytes(env, o, 2, sealed, plen + 40);
    free(sealed);
    *out_len = o;
    return env;
}

/* Decrypts the envelope in place, without another copy of the message. Returns a pointer to the
 * plaintext inside env, or NULL. */
static uint8_t *mgmt_open(uint8_t *env, size_t elen, size_t *plen)
{
    const uint8_t *body;
    size_t bl;
    if (nbl_get_bytes(env, elen, 2, &body, &bl) < 0) {
        return NULL;
    }
    uint8_t *b = env + (body - env); /* the same buffer, writable */
    int n = nbl_box_open_inplace(b, bl, C.srv_shared);
    if (n < 0) {
        return NULL;
    }
    *plen = (size_t)n;
    return b + 40;
}

static int mgmt_get_server_key(void)
{
    uint8_t *resp = NULL;
    size_t rl = 0;
    int st = -1;
    char gm[96] = "";
    int rc = nbl_h2_unary(C.mgmt, PATH_MGMT "GetServerKey", (const uint8_t *)"", 0, &resp, &rl, &st, gm,
                          sizeof(gm), 15000);
    if (rc != 0) {
        set_err("GetServerKey failed (%s)", gm[0] ? gm : "timeout/transport");
        free(resp);
        return -1;
    }
    management_ServerKeyResponse k = management_ServerKeyResponse_init_zero;
    pb_istream_t is = pb_istream_from_buffer(resp, rl);
    bool ok = pb_decode(&is, management_ServerKeyResponse_fields, &k);
    free(resp);
    uint8_t spub[32];
    if (!ok || nbl_b64_dec(k.key, spub, sizeof(spub)) != 32) {
        set_err("%s", "invalid server key");
        return -1;
    }
    return nbl_box_precompute(C.srv_shared, spub, C.priv);
}

static void reg_flag_set(bool on)
{
    C.registered = on;
    nvs_handle_t n;
    if (nvs_open(NBL_NVS_NS, NVS_READWRITE, &n) == ESP_OK) {
        if (on) {
            nvs_set_u8(n, NBL_NVS_REG, 1);
        } else {
            nvs_erase_key(n, NBL_NVS_REG);
        }
        nvs_commit(n);
        nvs_close(n);
    }
}

static void login_fatal(const char *fmt, const char *a)
{
    snprintf(C.st.last_error, sizeof(C.st.last_error), fmt, a ? a : "");
    ESP_LOGE(TAG, "%s (next attempt in %d s)", C.st.last_error, FATAL_RETRY_S);
    set_state(NBL_FATAL);
}

/* Login answers of NetBird v0.80.0 (management/internals/shared/grpc/server.go Login, mapError;
 * management/server/peer.go LoginPeer/AddPeer):
 *   PERMISSION_DENIED (7)    peer key unknown and no setup key sent ("no peer auth method
 *                            provided"); SSO peers also: login expired, user blocked/pending
 *   NOT_FOUND (5)            setup key unknown, revoked, expired or used up ("setup key is invalid")
 *   FAILED_PRECONDITION (9)  registration race ("peer has been already registered", key used up
 *                            meanwhile): a retry gets the final answer
 *   INVALID_ARGUMENT (3)     the server could not decrypt the request (e.g. its key changed
 *                            between GetServerKey and Login) or our key is malformed
 *   INTERNAL (13), UNKNOWN (2, e.g. the same key logged in elsewhere), transport errors: transient
 * Only PERMISSION_DENIED after a login without setup key means "not registered": then the flag is
 * cleared and, like the official client, the setup key is sent right away. Returns 0, or -1 (state
 * NBL_FATAL for rejections that a retry cannot fix soon). */
static int mgmt_login(void)
{
    bool with_key = !C.registered && C.setup_key[0];
    for (int attempt = 0; attempt < 2; attempt++) {
        management_LoginRequest req = management_LoginRequest_init_zero;
        if (with_key) {
            strlcpy(req.setupKey, C.setup_key, sizeof(req.setupKey));
        }
        req.has_meta = true;
        fill_meta(&req.meta);
        uint8_t buf[512];
        pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof(buf));
        if (!pb_encode(&os, management_LoginRequest_fields, &req)) {
            return -1;
        }
        size_t el;
        uint8_t *env = mgmt_envelope(buf, os.bytes_written, &el);
        if (!env) {
            return -1;
        }
        uint8_t *resp = NULL;
        size_t rl = 0;
        int st = -1;
        char gm[96] = "";
        int rc = nbl_h2_unary(C.mgmt, PATH_MGMT "Login", env, el, &resp, &rl, &st, gm, sizeof(gm), 20000);
        free(env);
        if (rc == 0) {
            size_t pl;
            bool ok = mgmt_open(resp, rl, &pl) != NULL;
            free(resp);
            if (!ok) {
                set_err("%s", "cannot decrypt login response");
                return -1;
            }
            if (!C.registered) {
                reg_flag_set(true);
                ESP_LOGI(TAG, "Peer registered, the setup key is no longer sent");
            }
            return 0;
        }
        free(resp);
        if (rc != -3) {
            set_err("Login failed (%s)", gm[0] ? gm : "timeout/transport");
            return -1;
        }
        if (st == GRPC_PERMISSION_DENIED && !with_key) {
            if (C.registered) {
                ESP_LOGW(TAG, "Management does not know this peer (%s)", gm);
            }
            reg_flag_set(false);
            if (C.setup_key[0]) {
                with_key = true;
                continue;
            }
            login_fatal("Peer not registered and no setup key: %.60s", gm);
            return -1;
        }
        if (st == GRPC_NOT_FOUND && with_key) {
            login_fatal("Setup key rejected: %.70s", gm);
            return -1;
        }
        if (st == GRPC_PERMISSION_DENIED || st == GRPC_NOT_FOUND) {
            login_fatal("Login rejected: %.75s", gm);
            return -1;
        }
        snprintf(C.st.last_error, sizeof(C.st.last_error), "Login failed (grpc %d): %.60s", st, gm);
        ESP_LOGW(TAG, "%s", C.st.last_error);
        st_publish();
        return -1;
    }
    return -1;
}

/* ============================== Signal ============================== */

static bool cb_enc_str(pb_ostream_t *s, const pb_field_t *f, void *const *arg)
{
    const char *str = *arg;
    return pb_encode_tag_for_field(s, f) && pb_encode_string(s, (const pb_byte_t *)str, strlen(str));
}

static void sig_send_on_close(void *ctx, int st, const char *gm, uint32_t err)
{
    (void)ctx;
    if (st != 0) {
        ESP_LOGW(TAG, "Signal send failed (grpc %d, h2 %u): %s", st, (unsigned)err, gm);
    }
}

/* OFFER/ANSWER without ICE: the remote peer opens its relay path to our relay instance.
 * Not sent: Rosenpass config (Rosenpass is not supported), session ID, relay IP. */
static void sig_send_body(peer_t *p, signalexchange_Body_Type type)
{
    if (C.sig_state != SIG_UP || !C.sig) {
        return;
    }
    char inst[RELAY_ADDR_CAP + 1];
    nbl_relay_get_instance(inst, sizeof(inst));
    if (strlen(inst) >= RELAY_ADDR_CAP) {
        ESP_LOGE(TAG, "Relay instance URL too long, not announced"); /* never sent truncated */
        return;
    }
    signalexchange_Body b = signalexchange_Body_init_zero;
    b.type = type;
    b.payload.funcs.encode = cb_enc_str;
    b.payload.arg = ":"; /* empty ICE credentials "ufrag:pwd": upstream peers then skip ICE */
    b.wgListenPort = 51820;
    b.netBirdVersion.funcs.encode = cb_enc_str;
    b.netBirdVersion.arg = NBL_VERSION;
    if (inst[0]) {
        b.relayServerAddress.funcs.encode = cb_enc_str;
        b.relayServerAddress.arg = inst;
    }
    uint8_t pb[320];
    pb_ostream_t os = pb_ostream_from_buffer(pb, sizeof(pb));
    if (!pb_encode(&os, signalexchange_Body_fields, &b)) {
        return;
    }
    uint8_t sealed[sizeof(pb) + 40];
    int sl = nbl_box_seal(sealed, p->shared, pb, os.bytes_written);
    if (sl < 0) {
        return;
    }
    uint8_t env[sizeof(sealed) + 2 * (NBL_KEY_B64 + 2) + 3];
    size_t o = nbl_put_bytes(env, 0, 2, C.pub_b64, strlen(C.pub_b64));
    o = nbl_put_bytes(env, o, 3, p->key, strlen(p->key));
    o = nbl_put_bytes(env, o, 4, sealed, (size_t)sl);
    nbl_stream_cb_t cb = {.on_close = sig_send_on_close};
    nbl_stream_t *st = nbl_h2_call(C.sig, PATH_SIGNAL_SEND, NULL, NULL, &cb, NULL);
    int rc = -1;
    if (st) {
        nbl_h2_set_deadline(st, 10000); /* a lost answer must not hold a stream slot */
        rc = nbl_h2_send(st, env, o, true);
    }
    ESP_LOGI(TAG, "Signal -> %.8s: %s (%u B, rc %d)", p->key, type == signalexchange_Body_Type_OFFER ? "OFFER" : "ANSWER",
             (unsigned)o, rc);
}

static void sig_on_msg(void *ctx, const uint8_t *msg, size_t len)
{
    (void)ctx;
    const uint8_t *k, *body;
    size_t kl, bl;
    if (nbl_get_bytes(msg, len, 2, &k, &kl) < 0 || nbl_get_bytes(msg, len, 4, &body, &bl) < 0 || kl > NBL_KEY_B64) {
        return;
    }
    char key[NBL_KEY_B64 + 1];
    memcpy(key, k, kl);
    key[kl] = 0;
    peer_t *p = peer_by_key(key);
    if (!p) {
        ESP_LOGD(TAG, "Ignoring signal from unknown peer %.8s", key);
        return;
    }
    /* Decrypted in place: msg is the gRPC layer's own reassembly buffer, allocated for this one
     * message and freed right after the callback (nbl_grpc_rx_feed). */
    uint8_t *box = (uint8_t *)msg + (body - msg);
    int n = nbl_box_open_inplace(box, bl, p->shared);
    char ver[32], relay[RELAY_ADDR_CAP];
    nbl_pb_str_t va = {ver, sizeof(ver), false, false}, ra = {relay, sizeof(relay), false, false};
    ver[0] = relay[0] = 0;
    signalexchange_Body b = signalexchange_Body_init_zero;
    b.netBirdVersion.funcs.decode = nbl_pb_decode_str;
    b.netBirdVersion.arg = &va;
    b.relayServerAddress.funcs.decode = nbl_pb_decode_str;
    b.relayServerAddress.arg = &ra;
    bool ok = false;
    if (n >= 0) {
        pb_istream_t is = pb_istream_from_buffer(box + 40, (size_t)n);
        ok = pb_decode(&is, signalexchange_Body_fields, &b);
    }
    if (!ok) {
        ESP_LOGW(TAG, "Unreadable signal message from %.8s", key);
        return;
    }
    switch (b.type) {
    case signalexchange_Body_Type_OFFER:
    case signalexchange_Body_Type_ANSWER:
        ESP_LOGI(TAG, "%s from %.8s (version %s, relay %s)", b.type == signalexchange_Body_Type_OFFER ? "OFFER" : "ANSWER",
                 key, va.bad ? "?" : ver, relay[0] ? relay : "-");
        if (ra.bad) {
            ESP_LOGW(TAG, "Peer %.8s announced a relay URL longer than %d characters, no path to it", key,
                     RELAY_ADDR_CAP - 1);
            break;
        }
        if (!relay[0]) {
            ESP_LOGW(TAG, "Peer %.8s announced no relay server, no path to it", key);
            break;
        }
        memcpy(p->remote_relay, relay, sizeof(p->remote_relay));
        p->remote_known = true;
        if (b.type == signalexchange_Body_Type_OFFER) {
            p->need_answer = true; /* sent from the session loop, with our relay address */
        }
        break;
    default:
        break;
    }
}

static void sig_on_header(void *ctx, const char *n, const char *v)
{
    (void)ctx;
    (void)v;
    if (!strcasecmp(n, "x-wiretrustee-peer-registered")) {
        C.sig_registered = true;
    }
}

static void sig_on_close(void *ctx, int st, const char *gm, uint32_t err)
{
    (void)ctx;
    ESP_LOGW(TAG, "Signal stream closed (grpc %d, h2 %u): %s", st, (unsigned)err, gm);
    C.sig_closed = true;
}

/* Releases stream and dedicated connection (no callbacks follow). */
static void sig_drop(void)
{
    if (C.sig && C.sig != C.mgmt) {
        nbl_h2_free(C.sig);
    }
    C.sig = NULL;
    C.sig_registered = false;
    C.sig_closed = false;
    if (C.st.signal_up) {
        C.st.signal_up = false;
        st_publish();
    }
}

/* Transport loss, failed connect, stream end or missing registration: retry with backoff. */
static void sig_fail(const char *why)
{
    int64_t now = esp_timer_get_time();
    if (C.sig_state == SIG_UP && now - C.sig_up_us > SIG_STABLE_US) {
        C.sig_backoff_s = SIG_RETRY_MIN_S;
    }
    sig_drop();
    uint32_t ms = jitter_ms(C.sig_backoff_s);
    C.sig_backoff_s = backoff_next(C.sig_backoff_s, SIG_RETRY_MAX_S);
    C.sig_next_us = now + (int64_t)ms * 1000;
    C.sig_state = SIG_WAIT;
    ESP_LOGW(TAG, "Signal: %s, retrying in %u ms", why, (unsigned)ms);
}

static void sig_open_stream(int64_t now)
{
    nbl_stream_cb_t cb = {.on_header = sig_on_header, .on_msg = sig_on_msg, .on_close = sig_on_close};
    C.sig_registered = false;
    C.sig_closed = false;
    if (!nbl_h2_call(C.sig, PATH_SIGNAL, "x-wiretrustee-peer-id", C.pub_b64, &cb, NULL)) {
        sig_fail("cannot open ConnectStream");
        return;
    }
    C.sig_state = SIG_REGISTERING;
    C.sig_deadline_us = now + SIG_REGISTER_US;
}

struct sig_open_req {
    char host[HOST_CAP];
    int port;
};

/* The TLS handshake takes seconds. The management server pings after 5 s without traffic and
 * closes the connection if the ACK takes longer than 2 s (grpc-go keepalive), so a dedicated
 * signal connection is opened in this short-lived task and handed over through C.sig_q; the
 * control task alone uses it afterwards. */
static void sig_open_task(void *arg)
{
    struct sig_open_req *r = arg;
    nbl_h2_t *h = nbl_h2_open(r->host, r->port, 15000);
    free(r);
    xQueueSend(C.sig_q, &h, portMAX_DELAY);
    vTaskDelete(NULL);
}

static void sig_start(int64_t now)
{
    if (C.sig_inflight) {
        return; /* a previous open still runs: wait for its result */
    }
    if (!strcmp(C.sig_host, C.mgmt_host) && C.sig_port == C.mgmt_port) {
        C.sig = C.mgmt; /* same server: share the management connection */
        sig_open_stream(now);
        return;
    }
    struct sig_open_req *r = malloc(sizeof(*r));
    if (!r) {
        sig_fail("out of memory");
        return;
    }
    strlcpy(r->host, C.sig_host, sizeof(r->host));
    r->port = C.sig_port;
    strlcpy(C.sig_open_host, C.sig_host, sizeof(C.sig_open_host));
    C.sig_open_port = C.sig_port;
    if (xTaskCreate(sig_open_task, "nbl_sigopen", SIG_OPEN_STACK, r, 5, NULL) != pdPASS) {
        free(r);
        sig_fail("cannot start the connect task");
        return;
    }
    C.sig_inflight = true;
    C.sig_state = SIG_OPENING;
}

/* Runs once per session loop iteration. Returns false if the session has to end. */
static bool sig_service(void)
{
    int64_t now = esp_timer_get_time();
    nbl_h2_t *h;
    if (C.sig_inflight && xQueueReceive(C.sig_q, &h, 0) == pdTRUE) {
        C.sig_inflight = false;
        if (C.sig_state != SIG_OPENING || strcmp(C.sig_open_host, C.sig_host) != 0 || C.sig_open_port != C.sig_port) {
            nbl_h2_free(h); /* no longer wanted */
        } else if (!h) {
            set_err("Signal connection to %s failed", C.sig_open_host);
            sig_fail("connection failed");
        } else {
            C.sig = h;
            sig_open_stream(now);
        }
    }
    switch (C.sig_state) {
    case SIG_IDLE:
        if (C.sig_host[0]) {
            C.sig_state = SIG_WAIT;
            C.sig_next_us = now;
        }
        break;
    case SIG_WAIT:
        if (now >= C.sig_next_us) {
            sig_start(now);
        }
        break;
    case SIG_OPENING:
        break;
    case SIG_REGISTERING:
    case SIG_UP:
        if (C.sig != C.mgmt && nbl_h2_run(C.sig, 0) < 0) {
            sig_fail("connection lost");
            break;
        }
        if (C.sig_closed) {
            sig_fail("stream ended");
            break;
        }
        if (C.sig_state == SIG_REGISTERING) {
            if (C.sig_registered) {
                C.sig_state = SIG_UP;
                C.sig_up_us = now;
                C.st.signal_up = true;
                st_publish();
                ESP_LOGI(TAG, "Signal stream registered");
                for (int i = 0; i < MAX_PEERS; i++) {
                    if (C.peers[i].used && !C.peers[i].up) {
                        C.peers[i].offers = 0; /* offer again right away */
                    }
                }
            } else if (now > C.sig_deadline_us) {
                if (C.sig == C.mgmt) {
                    /* a stream on the shared connection cannot be cancelled */
                    set_err("%s", "Signal registration timed out");
                    return false;
                }
                sig_fail("no registration from the signal server");
            }
        }
        break;
    }
    return true;
}

/* Signal server from the management config. */
static void sig_want(const char *uri, int32_t proto)
{
    char host[HOST_CAP];
    int port;
    if (proto != 0 && proto != 3 /* HTTPS */) {
        set_err("Unsupported signal protocol for %s (HTTPS only)", uri);
        return;
    }
    if (parse_url(uri, host, sizeof(host), &port) < 0) {
        set_err("Cannot parse signal URI %s", uri);
        return;
    }
    if (!strcmp(host, C.sig_host) && port == C.sig_port) {
        return;
    }
    ESP_LOGI(TAG, "Signal server %s:%d", host, port);
    bool shared = C.sig && C.sig == C.mgmt;
    strlcpy(C.sig_host, host, sizeof(C.sig_host));
    C.sig_port = port;
    if (shared) {
        C.restart = true; /* the stream on the management connection cannot be cancelled */
        return;
    }
    sig_drop();
    C.sig_state = SIG_WAIT;
    C.sig_next_us = esp_timer_get_time();
    C.sig_backoff_s = SIG_RETRY_MIN_S;
}

/* Answers to offers, once our relay is up (the answer carries our relay address). */
static void sig_flush_answers(void)
{
    if (C.sig_state != SIG_UP || !nbl_relay_up()) {
        return;
    }
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &C.peers[i];
        if (p->used && p->need_answer) {
            p->need_answer = false;
            sig_send_body(p, signalexchange_Body_Type_ANSWER);
        }
    }
}

/* ============================== Peers / network map ============================== */

static int wg_tx(int tag, const uint8_t *pkt, size_t len)
{
    int i = tag - 1;
    if (i < 0 || i >= MAX_PEERS || !C.peers[i].used) {
        return -1;
    }
    return nbl_relay_send(C.peers[i].relay_id, pkt, len);
}

static void relay_rx(const uint8_t src_id[NBL_RELAY_ID_LEN], const uint8_t *wg, size_t len)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (C.peers[i].used && !memcmp(C.peers[i].relay_id, src_id, NBL_RELAY_ID_LEN)) {
            nbl_wg_rx(i + 1, wg, len);
            return;
        }
    }
}

static void peer_remove(peer_t *p)
{
    ESP_LOGI(TAG, "Peer %.8s removed", p->key);
    if (nbl_wg_remove_peer(p->wg_slot) != ESP_OK) {
        ESP_LOGW(TAG, "WireGuard slot of peer %.8s not freed", p->key); /* inert: its tag is unused now */
    }
    memset(p, 0, sizeof(*p));
}

static void peer_add(const nbl_nm_peer_t *np)
{
    int idx = -1;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!C.peers[i].used) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return;
    }
    uint8_t pub[32];
    if (nbl_b64_dec(np->key, pub, sizeof(pub)) != 32) {
        ESP_LOGW(TAG, "Peer %.8s has an invalid key, skipped", np->key);
        return;
    }
    peer_t *p = &C.peers[idx];
    memset(p, 0, sizeof(*p));
    strlcpy(p->key, np->key, sizeof(p->key));
    memcpy(p->pub, pub, 32);
    p->ip4 = np->ip4;
    p->wg_slot = -1;
    nbl_relay_id(p->key, p->relay_id);
    if (nbl_box_precompute(p->shared, p->pub, C.priv) < 0) {
        return;
    }
    p->used = true; /* set before wg_add: relay RX and WireGuard TX may use the entry right away */
    p->wg_slot = nbl_wg_add_peer(p->key, p->ip4, 32, idx + 1);
    if (p->wg_slot < 0) {
        ESP_LOGE(TAG, "Failed to add WireGuard peer %.8s", p->key);
        memset(p, 0, sizeof(*p));
        return;
    }
    char ipbuf[16];
    inet_ntop(AF_INET, &p->ip4, ipbuf, sizeof(ipbuf));
    ESP_LOGI(TAG, "Peer %.8s added (%s)", p->key, ipbuf);
}

/* The overlay address of a known peer changed: its WireGuard peer is re-added with the new
 * allowed IP in the same table slot, so tag, relay ID and the signaling state (remote relay,
 * pending answer) stay valid; tick() connects it again. */
static void peer_readd(peer_t *p, uint32_t ip4)
{
    char ipbuf[16];
    inet_ntop(AF_INET, &ip4, ipbuf, sizeof(ipbuf));
    ESP_LOGI(TAG, "Peer %.8s moved to %s", p->key, ipbuf);
    nbl_wg_remove_peer(p->wg_slot); /* if this fails, nbl_wg_add_peer() replaces the old entry */
    p->ip4 = ip4;
    p->up = false;
    p->wg_requested = false;
    p->wg_slot = nbl_wg_add_peer(p->key, ip4, 32, (int)(p - C.peers) + 1);
    if (p->wg_slot < 0) {
        ESP_LOGE(TAG, "Failed to re-add WireGuard peer %.8s", p->key);
        memset(p, 0, sizeof(*p));
    }
}

static void apply_peerconfig(const char *address, int32_t mtu_cfg)
{
    uint32_t ip;
    int pfx;
    if (!nbl_nm_parse_ip4(address, &ip, &pfx) || pfx < 1) {
        ESP_LOGW(TAG, "Cannot parse address '%s'", address);
        return;
    }
    if (C.ip_set && ip == C.my_ip && pfx == C.my_prefix) {
        return;
    }
    int mtu = mtu_cfg > 576 && mtu_cfg <= 1420 ? mtu_cfg : CONFIG_NBL_MTU;
    if (nbl_wg_set_ip(ip, (uint8_t)pfx, mtu) != ESP_OK) {
        set_err("Setting the NetBird address %s failed, reconnecting", address);
        C.restart = true; /* the next session delivers the map again */
        return;
    }
    C.my_ip = ip;
    C.my_prefix = (uint8_t)pfx;
    C.ip_set = true;
    strlcpy(C.st.ip, address, sizeof(C.st.ip));
    ESP_LOGI(TAG, "NetBird address %s (MTU %d)", address, mtu);
}

/* Installs a rule set. If that fails the previous rules stay in force, so a copy is retried by
 * tick() every second; without memory for the copy the session restarts (fresh map). */
static void acl_apply(const nbl_acl_rule_t *rules, int n)
{
    free(C.acl_pending);
    C.acl_pending = NULL;
    if (nbl_acl_set(rules, (size_t)n) == ESP_OK) {
        C.st.acl_rules = n;
        return;
    }
    C.acl_pending = malloc(n ? (size_t)n * sizeof(*rules) : 1);
    if (!C.acl_pending) {
        set_err("%s", "Firewall update failed, reconnecting");
        C.restart = true;
        return;
    }
    memcpy(C.acl_pending, rules, (size_t)n * sizeof(*rules));
    C.acl_pending_n = n;
    ESP_LOGW(TAG, "Firewall update failed, retrying");
}

static void apply_map(const nbl_netmap_t *nm)
{
    /* the address first, as the official client does: it may change without a new serial */
    if (nm->has_peer_config) {
        apply_peerconfig(nm->address, nm->mtu);
    }
    if (!C.ip_set) {
        return; /* no address means no netif, hence no peers */
    }
    if (C.have_serial && nm->serial < C.serial) {
        /* %lu, not %llu: newlib nano printf (CONFIG_NEWLIB_NANO_FORMAT) has no 64-bit formats */
        ESP_LOGW(TAG, "Ignoring an outdated network map (serial %lu < %lu)", (unsigned long)nm->serial,
                 (unsigned long)C.serial);
        return;
    }
    C.have_serial = true;
    C.serial = nm->serial;

    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &C.peers[i];
        if (!p->used) {
            continue;
        }
        const nbl_nm_peer_t *np = NULL;
        for (int j = 0; j < nm->n_peers; j++) {
            if (!strcmp(p->key, nm->peers[j].key)) {
                np = &nm->peers[j];
                break;
            }
        }
        if (!np) {
            peer_remove(p);
        } else if (np->ip4 != p->ip4) {
            peer_readd(p, np->ip4);
        }
    }
    for (int j = 0; j < nm->n_peers; j++) {
        if (!peer_by_key(nm->peers[j].key)) {
            peer_add(&nm->peers[j]);
        }
    }
    int usable = nm->peers_total - nm->peers_unusable;
    if (usable > MAX_PEERS) {
        ESP_LOGW(TAG, "%d peers in the network map, only %d supported (CONFIG_NBL_MAX_PEERS)", usable, MAX_PEERS);
    }
    if (nm->peers_unusable) {
        ESP_LOGW(TAG, "%d peer(s) without a valid key or IPv4 address skipped", nm->peers_unusable);
    }
    int n = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        n += C.peers[i].used;
    }
    C.st.peers = n;

    acl_apply(nm->rules, nm->n_rules);
    ESP_LOGI(TAG, "Network map (serial %lu): %d peer(s), %d ACL entr%s from %d firewall rule(s): %d not "
                  "applicable, %d malformed",
             (unsigned long)nm->serial, n, nm->n_rules, nm->n_rules == 1 ? "y" : "ies", nm->fw_total, nm->fw_skipped,
             nm->fw_malformed);
    if (nm->fw_truncated) {
        ESP_LOGW(TAG, "Firewall rules truncated: %d entr%s over CONFIG_NBL_MAX_RULES (%d) dropped", nm->fw_truncated,
                 nm->fw_truncated == 1 ? "y" : "ies", CONFIG_NBL_MAX_RULES);
    }
    if (nm->deny_lost) {
        ESP_LOGE(TAG, "A DROP rule could not be applied (malformed or over CONFIG_NBL_MAX_RULES): "
                      "no inbound traffic is accepted");
    }
    C.synced = true;
    set_state(NBL_SYNCED);
}

static void apply_sync(const uint8_t *pt, size_t len)
{
    nbl_netmap_t *nm = calloc(1, sizeof(*nm));
    nbl_nm_peer_t *peers = calloc(MAX_PEERS, sizeof(*peers));
    nbl_acl_rule_t *rules = calloc(CONFIG_NBL_MAX_RULES, sizeof(*rules));
    if (!nm || !peers || !rules) {
        set_err("%s", "Out of memory for the network map, reconnecting");
        C.restart = true;
        goto done;
    }
    nm->peers = peers;
    nm->max_peers = MAX_PEERS;
    nm->rules = rules;
    nm->max_rules = CONFIG_NBL_MAX_RULES;
    nm->own_key = C.pub_b64;
    if (nbl_netmap_decode(pt, len, nm) < 0) {
        ESP_LOGW(TAG, "Cannot decode SyncResponse: %s", nm->error ? nm->error : "?");
        goto done;
    }
    if (nm->config_too_long) {
        ESP_LOGE(TAG, "Signal URI or relay token longer than supported, ignored");
    }
    if (nm->relay_urls_too_long) {
        ESP_LOGW(TAG, "%d of %d relay URL(s) longer than %d characters ignored", nm->relay_urls_too_long,
                 nm->relay_urls, NBL_NM_RELAY_URL_CAP - 1);
    }
    if (nm->has_relay) {
        /* only one relay connection: remote peers must be reachable through this relay */
        nbl_relay_configure(nm->relay_url, nm->relay_payload, nm->relay_sig, C.pub_b64);
    }
    if (nm->has_signal) {
        sig_want(nm->signal_uri, nm->signal_protocol);
    }
    if (nm->has_map) {
        apply_map(nm);
    }
done:
    free(rules);
    free(peers);
    free(nm);
}

static void sync_on_msg(void *ctx, const uint8_t *msg, size_t len)
{
    (void)ctx;
    size_t pl;
    /* Decrypted in place: msg is the gRPC layer's own reassembly buffer, allocated for this one
     * message and freed right after the callback (nbl_grpc_rx_feed). No second 48 KB copy. */
    const uint8_t *pt = mgmt_open((uint8_t *)msg, len, &pl);
    if (!pt) {
        ESP_LOGW(TAG, "Cannot decrypt sync message");
        return;
    }
    apply_sync(pt, pl);
}

static void sync_on_close(void *ctx, int st, const char *gm, uint32_t err)
{
    (void)ctx;
    ESP_LOGW(TAG, "Sync stream closed (grpc %d, h2 %u): %s", st, (unsigned)err, gm);
    C.sync_s = NULL;
    C.sync_closed = true;
}

static int mgmt_start_sync(void)
{
    management_SyncRequest req = management_SyncRequest_init_zero;
    req.has_meta = true;
    fill_meta(&req.meta);
    uint8_t buf[512];
    pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof(buf));
    if (!pb_encode(&os, management_SyncRequest_fields, &req)) {
        return -1;
    }
    size_t el;
    uint8_t *env = mgmt_envelope(buf, os.bytes_written, &el);
    if (!env) {
        return -1;
    }
    nbl_stream_cb_t cb = {.on_msg = sync_on_msg, .on_close = sync_on_close};
    C.sync_closed = false;
    C.sync_s = nbl_h2_call(C.mgmt, PATH_MGMT "Sync", NULL, NULL, &cb, NULL);
    int rc = -1;
    if (C.sync_s) {
        rc = nbl_h2_send(C.sync_s, env, el, true);
    }
    free(env);
    if (rc < 0) {
        set_err("%s", "Cannot start the sync stream");
    }
    return rc;
}

/* ============================== Periodic tick ============================== */

static void tick(void)
{
    int64_t now = esp_timer_get_time();
    if (now - C.last_tick_us < 1000000) {
        return;
    }
    C.last_tick_us = now;

    bool relay = nbl_relay_up();
    char inst[RELAY_ADDR_CAP + 1] = "";
    if (relay) {
        nbl_relay_get_instance(inst, sizeof(inst));
    }
    int up = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &C.peers[i];
        if (!p->used) {
            continue;
        }
        p->up = nbl_wg_peer_up(p->wg_slot);
        up += p->up;
        if (p->up) {
            continue;
        }
        if (relay && C.sig_state == SIG_UP && (p->offers == 0 || now - p->last_offer_us > OFFER_EVERY_US)) {
            ESP_LOGI(TAG, "OFFER to %.8s", p->key);
            sig_send_body(p, signalexchange_Body_Type_OFFER);
            p->last_offer_us = now;
            p->offers++;
        }
        if (p->remote_known && relay && !p->wg_requested) {
            if (strcmp(p->remote_relay, inst) != 0) {
                ESP_LOGW(TAG, "Peer %.8s is on a different relay (%s), no common path", p->key, p->remote_relay);
            }
            p->wg_requested = nbl_wg_connect(p->wg_slot) == ESP_OK; /* otherwise the next tick retries */
        }
    }
    C.st.peers_up = up;
    C.st.relay_up = relay;
    if (C.acl_pending && nbl_acl_set(C.acl_pending, (size_t)C.acl_pending_n) == ESP_OK) {
        C.st.acl_rules = C.acl_pending_n;
        free(C.acl_pending);
        C.acl_pending = NULL;
    }

    nbl_relay_stats_t rs;
    nbl_relay_stats(&rs);
    C.st.relay_rx = rs.rx_pkts;
    C.st.relay_tx = rs.tx_pkts;
    C.st.relay_dropped = rs.dropped;
    C.st.relay_reconnects = rs.reconnects;
    nbl_wg_stats_t ws;
    nbl_wg_stats(&ws);
    C.st.acl_pass = ws.acl_pass;
    C.st.acl_drop = ws.acl_drop;
    st_publish();
}

/* ============================== Task ============================== */

static void wait_for_time(void)
{
    if (time(NULL) > 1700000000) {
        return;
    }
    set_state(NBL_WAIT_TIME);
#if CONFIG_NBL_SNTP
    if (!esp_sntp_enabled()) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, CONFIG_NBL_SNTP_SERVER);
        esp_sntp_init();
    }
#endif
    ESP_LOGI(TAG, "Waiting for a valid system time");
    while (time(NULL) < 1700000000 && !C.stop) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

static void session_end(void)
{
    sig_drop(); /* before the management connection: it may be shared */
    C.sig_state = SIG_IDLE;
    C.sync_s = NULL;
    nbl_h2_free(C.mgmt);
    C.mgmt = NULL;
    /* fresh offers to every peer once the next session is up; pending answers are stale */
    for (int i = 0; i < MAX_PEERS; i++) {
        C.peers[i].offers = 0;
        C.peers[i].need_answer = false;
    }
}

/* One management session. Returns true if it applied a network map. */
static bool session(void)
{
    C.synced = false;
    C.restart = false;
    C.have_serial = false;
    C.sig_state = SIG_IDLE;
    C.sig_backoff_s = SIG_RETRY_MIN_S;
    set_state(NBL_CONNECTING);
    C.mgmt = nbl_h2_open(C.mgmt_host, C.mgmt_port, 15000);
    if (!C.mgmt) {
        set_err("Connection to management %s failed", C.mgmt_host);
        return false;
    }
    set_state(NBL_LOGIN);
    if (mgmt_get_server_key() < 0 || mgmt_login() < 0 || mgmt_start_sync() < 0) {
        session_end();
        return false;
    }
    C.st.last_error[0] = 0;
    st_publish();
    ESP_LOGI(TAG, "Login OK, sync stream open");
    while (!C.stop) {
        if (nbl_h2_run(C.mgmt, 100) < 0) {
            set_err("%s", "Management connection lost");
            break;
        }
        if (C.sync_closed) {
            set_err("%s", "Sync stream closed by server");
            break;
        }
        if (C.restart || !sig_service()) {
            break;
        }
        sig_flush_answers();
        tick();
    }
    session_end();
    return C.synced;
}

static void ctrl_task(void *arg)
{
    (void)arg;
    int backoff = RETRY_MIN_S;
    while (!C.stop) {
        wait_for_time();
        if (C.stop) {
            break;
        }
        if (session()) {
            backoff = RETRY_MIN_S; /* the session worked: retry soon */
        }
        if (C.stop) {
            break;
        }
        uint32_t wait_ms;
        if (C.st.state == NBL_FATAL) {
            wait_ms = FATAL_RETRY_S * 1000; /* in case the administrator fixes it */
        } else {
            set_state(NBL_RETRY_WAIT);
            wait_ms = jitter_ms(backoff);
            backoff = backoff_next(backoff, RETRY_MAX_S);
        }
        ESP_LOGI(TAG, "Next management connection in %u ms", (unsigned)wait_ms);
        for (uint32_t t = 0; t < wait_ms && !C.stop; t += 100) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    if (C.sig_inflight) { /* the connect task finishes within its 15 s timeout */
        nbl_h2_t *h = NULL;
        if (xQueueReceive(C.sig_q, &h, pdMS_TO_TICKS(30000)) == pdTRUE) {
            nbl_h2_free(h);
        }
        C.sig_inflight = false;
    }
    set_state(NBL_IDLE);
    C.task = NULL;
    vTaskDelete(NULL);
}

/* ============================== API ============================== */

esp_err_t nbl_start(const nbl_config_t *cfg)
{
    if (s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!cfg || !cfg->management_url) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_st_mu && !(s_st_mu = xSemaphoreCreateMutex())) {
        return ESP_ERR_NO_MEM;
    }
    memset(&C, 0, sizeof(C));
    if (strlen(cfg->management_url) >= sizeof(C.mgmt_url) ||
        (cfg->setup_key && strlen(cfg->setup_key) >= sizeof(C.setup_key))) {
        return ESP_ERR_INVALID_ARG;
    }
    strlcpy(C.mgmt_url, cfg->management_url, sizeof(C.mgmt_url));
    if (cfg->setup_key) {
        strlcpy(C.setup_key, cfg->setup_key, sizeof(C.setup_key));
    }
    if (cfg->hostname && cfg->hostname[0]) {
        strlcpy(C.hostname, cfg->hostname, sizeof(C.hostname));
    } else {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(C.hostname, sizeof(C.hostname), "esp32-%02x%02x%02x", mac[3], mac[4], mac[5]);
    }
    if (parse_url(C.mgmt_url, C.mgmt_host, sizeof(C.mgmt_host), &C.mgmt_port) < 0) {
        return ESP_ERR_INVALID_ARG;
    }
    int created = 0;
    esp_err_t e = nbl_keys_load_or_create(C.priv, C.pub, &created);
    if (e != ESP_OK) {
        snprintf(C.st.last_error, sizeof(C.st.last_error), "Device key: NVS error %s, identity left unchanged",
                 esp_err_to_name(e));
        ESP_LOGE(TAG, "%s", C.st.last_error);
        set_state(NBL_FATAL);
        return e;
    }
    nbl_b64_enc(C.pub, 32, C.pub_b64, sizeof(C.pub_b64));
    strlcpy(C.st.pubkey, C.pub_b64, sizeof(C.st.pubkey));
    nvs_handle_t n;
    uint8_t reg = 0;
    if (nvs_open(NBL_NVS_NS, NVS_READONLY, &n) == ESP_OK) {
        nvs_get_u8(n, NBL_NVS_REG, &reg);
        nvs_close(n);
    }
    C.registered = reg == 1 && !created;
    if (!C.registered && !C.setup_key[0]) {
        ESP_LOGW(TAG, "No registration recorded and no setup key: trying a login with the stored key");
    }
    ESP_LOGI(TAG, "Key %s (%s), management %s:%d, name %s, version %s", C.pub_b64, created ? "new" : "stored",
             C.mgmt_host, C.mgmt_port, C.hostname, NBL_VERSION);

    C.sig_q = xQueueCreate(1, sizeof(nbl_h2_t *));
    if (!C.sig_q) {
        return ESP_ERR_NO_MEM;
    }
    if (nbl_wg_init(C.priv, wg_tx) != ESP_OK) {
        vQueueDelete(C.sig_q);
        return ESP_FAIL;
    }
#if CONFIG_NBL_ACL_ENFORCE
    nbl_acl_enforce(true);
#else
    nbl_acl_enforce(false);
#endif
    e = nbl_relay_start(relay_rx);
    if (e != ESP_OK) {
        vQueueDelete(C.sig_q);
        return e;
    }
    s_started = true; /* the relay task runs: there is no second start from here on */
    st_publish();
    if (xTaskCreate(ctrl_task, "nbl_ctrl", CONFIG_NBL_CTRL_STACK, NULL, 5, &C.task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

void nbl_stop(void)
{
    C.stop = true;
    nbl_relay_stop();
}

void nbl_get_status(nbl_status_t *out)
{
    if (!s_st_mu) {
        memset(out, 0, sizeof(*out));
        return;
    }
    xSemaphoreTake(s_st_mu, portMAX_DELAY);
    *out = s_st_pub;
    xSemaphoreGive(s_st_mu);
}

void nbl_forget(void)
{
    nbl_keys_erase();
}
