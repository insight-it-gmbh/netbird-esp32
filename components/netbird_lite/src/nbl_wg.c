// SPDX-License-Identifier: Apache-2.0
#include "nbl_wg.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "nbl_acl.h"
#include "nbl_crypto.h"
#include "wireguard-platform.h"
#include "wireguard.h"
#include "wireguardif.h"

static const char *TAG = "nbl_wg";

void wireguardif_network_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

/* ---------------- Platform hooks required by wireguard-lwip ---------------- */

uint32_t wireguard_sys_now(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

void wireguard_random_bytes(void *bytes, size_t size)
{
    esp_fill_random(bytes, size);
}

void wireguard_tai64n_now(uint8_t *out)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t sec = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
    uint32_t nsec = (uint32_t)tv.tv_usec * 1000;
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(sec >> (56 - 8 * i));
    }
    for (int i = 0; i < 4; i++) {
        out[8 + i] = (uint8_t)(nsec >> (24 - 8 * i));
    }
}

bool wireguard_is_under_load(void)
{
    return false;
}

/* ---------------- State ---------------- */

/* A WireGuard data message carries at most MTU bytes of padded plaintext plus 32 bytes of header
 * and tag; 16 bytes margin for peers that pad beyond the MTU. */
#define RX_OVERHEAD (32 + 16)
/* Relay packets waiting for the TCP/IP thread, in bytes: a peer sending junk at full speed must
 * not be able to exhaust the heap. */
#define RX_QUEUE_MAX (16 * 1024)

static struct netif s_netif;
static struct wireguardif_init_data s_init;
static char s_priv_b64[NBL_KEY_B64 + 1];
static nbl_wg_tx_fn s_tx;
static bool s_netif_ready;
static netif_output_fn s_wg_output; /* wireguardif_output(), wrapped by wg_output() */

/* Firewall state and rules: only used in lwIP context (TCP/IP thread or core lock), no locks */
static nbl_acl_state_t s_acl;
static nbl_acl_rule_t *s_rules;
static size_t s_nrules;

/* Shared with other tasks */
static atomic_bool s_enforce = true;
static _Atomic uint32_t s_acl_drop, s_acl_pass, s_rx_bad;
static _Atomic uint32_t s_rx_max; /* longest accepted relay packet; 0 = no interface yet */
static atomic_size_t s_rx_queued; /* bytes queued for the TCP/IP thread */

static void count(_Atomic uint32_t *c)
{
    atomic_fetch_add_explicit(c, 1, memory_order_relaxed);
}

static uint32_t now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

err_t nbl_wg_transport_send(u16_t tag, struct pbuf *q)
{
    if (!s_tx || tag == 0) {
        return ERR_RTE;
    }
    size_t len = q->tot_len;
    uint8_t *buf = malloc(len);
    if (!buf) {
        return ERR_MEM;
    }
    pbuf_copy_partial(q, buf, len, 0);
    int rc = s_tx(tag, buf, len);
    free(buf);
    return rc == 0 ? ERR_OK : ERR_IF;
}

/* Calls into the TCP/IP thread use tcpip_callback_wait(): it blocks until the function has run,
 * like lwIP's own netconn API, so the argument may live on the caller's stack. It only fails
 * (function not run) when no semaphore can be allocated. */

/* ---------------- Firewall (lwIP context) ---------------- */

/* netif->input: every decrypted packet passes the inbound filter before ip_input() */
static err_t wg_input(struct pbuf *p, struct netif *n)
{
    if (atomic_load_explicit(&s_enforce, memory_order_relaxed)) {
        uint8_t h[NBL_ACL_HDR_MAX];
        u16_t len = pbuf_copy_partial(p, h, sizeof(h), 0);
        if (!nbl_acl_check(&s_acl, s_rules, s_nrules, h, len, now_s())) {
            count(&s_acl_drop);
            pbuf_free(p);
            return ERR_OK;
        }
    }
    count(&s_acl_pass);
    return ip_input(p, n);
}

/* netif->output: records connections opened by this device so that their replies pass wg_input() */
static err_t wg_output(struct netif *n, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    uint8_t h[NBL_ACL_HDR_MAX];
    u16_t len = pbuf_copy_partial(p, h, sizeof(h), 0);
    nbl_acl_track(&s_acl, h, len, now_s());
    return s_wg_output(n, p, ipaddr);
}

struct acl_set_arg {
    nbl_acl_rule_t *rules;
    size_t n;
};

static void acl_set_cb(void *a)
{
    struct acl_set_arg *x = a;
    free(s_rules);
    s_rules = x->rules;
    s_nrules = x->n;
}

esp_err_t nbl_acl_set(const nbl_acl_rule_t *rules, size_t n)
{
    struct acl_set_arg a = {NULL, n};
    if (n) {
        a.rules = malloc(n * sizeof(*rules));
        if (!a.rules) {
            ESP_LOGE(TAG, "ACL: out of memory, keeping the previous rules");
            return ESP_ERR_NO_MEM;
        }
        memcpy(a.rules, rules, n * sizeof(*rules));
    }
    if (tcpip_callback_wait(acl_set_cb, &a) != ERR_OK) {
        free(a.rules);
        ESP_LOGE(TAG, "ACL: update failed, keeping the previous rules");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

void nbl_acl_enforce(bool on)
{
    atomic_store(&s_enforce, on);
}

/* ---------------- Netif / Peers ---------------- */

struct ip_arg {
    uint32_t ip;
    uint8_t prefix;
    int mtu;
    esp_err_t rc;
};

static void ip_cb(void *a)
{
    struct ip_arg *x = a;
    ip4_addr_t ip, mask;
    ip4_addr_set_u32(&ip, x->ip);
    ip4_addr_set_u32(&mask, htonl(0xffffffffu << (32 - x->prefix)));
    /* NOTE: once lwIP fires an address-change callback (netif_set_addr/ipaddr/netmask), ESP-IDF
     * casts netif->state to esp_netif_t, which crashes for netifs not created by esp_netif. So add
     * the netif without an address and write the fields directly (no callback; routing only reads
     * these fields). */
    if (!s_netif_ready) {
        if (!netif_add_noaddr(&s_netif, &s_init, wireguardif_init, wg_input)) {
            x->rc = ESP_FAIL;
            return;
        }
        s_wg_output = s_netif.output;
        s_netif.output = wg_output;
        s_netif_ready = true;
    }
    if (x->ip != s_acl.local_ip) {
        nbl_acl_init(&s_acl, x->ip); /* tracked connections belong to the old address */
    }
    ip_addr_copy_from_ip4(s_netif.ip_addr, ip);
    ip_addr_copy_from_ip4(s_netif.netmask, mask);
    s_netif.mtu = (u16_t)x->mtu;
    netif_set_up(&s_netif);
    /* The link stays up while the interface exists, with or without a WireGuard session: lwIP
     * routes around netifs without link, so traffic for NetBird addresses would leave unencrypted
     * through the default route. Without a session wireguardif_output() drops the packet (the
     * vendored wireguardif_tmr() no longer takes the link down). */
    netif_set_link_up(&s_netif);
    x->rc = ESP_OK;
}

esp_err_t nbl_wg_init(const uint8_t priv[32], nbl_wg_tx_fn tx)
{
    if (nbl_b64_enc(priv, 32, s_priv_b64, sizeof(s_priv_b64)) < 0) {
        return ESP_FAIL;
    }
    s_tx = tx;
    s_init.private_key = s_priv_b64;
    s_init.listen_port = 0; /* no UDP socket: the relay is the transport */
    s_init.bind_netif = NULL;
    return ESP_OK;
}

esp_err_t nbl_wg_set_ip(uint32_t ip4, uint8_t prefix, int mtu)
{
    /* prefix 0 would route all traffic into the tunnel */
    if (!ip4 || prefix < 1 || prefix > 32 || mtu < 576 || mtu > WIREGUARDIF_MTU) {
        return ESP_ERR_INVALID_ARG;
    }
    struct ip_arg a = {ip4, prefix, mtu, ESP_ERR_NO_MEM};
    if (tcpip_callback_wait(ip_cb, &a) != ERR_OK || a.rc != ESP_OK) {
        ESP_LOGE(TAG, "Configuring the WireGuard interface failed");
        return a.rc;
    }
    atomic_store(&s_rx_max, (uint32_t)mtu + RX_OVERHEAD);
    return ESP_OK;
}

struct peer_arg {
    const char *pub;
    uint32_t ip;
    uint8_t prefix;
    int tag;
    int slot;
};

static void add_peer_cb(void *a)
{
    struct peer_arg *x = a;
    x->slot = -1;
    if (!s_netif_ready) {
        return;
    }
    /* wireguardif_add_peer() returns the slot of an already registered key unchanged, with its old
     * allowed IP. Remove such a leftover (e.g. after a failed nbl_wg_remove_peer()) so that the
     * new settings apply. wireguardif_remove_peer() zeroes the whole peer, so the add below then
     * starts from a clean slot: remove + add with a changed address works. */
    struct wireguard_device *dev = s_netif.state;
    uint8_t key[WIREGUARD_PUBLIC_KEY_LEN];
    size_t kl = sizeof(key);
    if (wireguard_base64_decode(x->pub, key, &kl) && kl == sizeof(key)) {
        struct wireguard_peer *old = peer_lookup_by_pubkey(dev, key);
        if (old) {
            wireguardif_remove_peer(&s_netif, wireguard_peer_index(dev, old));
        }
    }
    struct wireguardif_peer p;
    wireguardif_peer_init(&p);
    p.public_key = x->pub;
    ip4_addr_set_u32(ip_2_ip4(&p.allowed_ip), x->ip);
    IP_SET_TYPE_VAL(p.allowed_ip, IPADDR_TYPE_V4);
    uint32_t m = x->prefix ? htonl(0xffffffffu << (32 - x->prefix)) : 0;
    ip4_addr_set_u32(ip_2_ip4(&p.allowed_mask), m);
    IP_SET_TYPE_VAL(p.allowed_mask, IPADDR_TYPE_V4);
    IP4_ADDR(ip_2_ip4(&p.endpoint_ip), 127, 0, 0, 1);
    IP_SET_TYPE_VAL(p.endpoint_ip, IPADDR_TYPE_V4);
    p.endport_port = (u16_t)x->tag;
    p.keep_alive = 25;
    u8_t idx;
    if (wireguardif_add_peer(&s_netif, &p, &idx) == ERR_OK && idx != WIREGUARDIF_INVALID_INDEX) {
        x->slot = idx;
    }
}

int nbl_wg_add_peer(const char *pub_b64, uint32_t ip4, uint8_t prefix, int tag)
{
    if (!pub_b64 || prefix > 32 || tag < 1 || tag > 0xffff) {
        return -1;
    }
    struct peer_arg a = {pub_b64, ip4, prefix, tag, -1};
    if (tcpip_callback_wait(add_peer_cb, &a) != ERR_OK) {
        return -1;
    }
    return a.slot;
}

struct slot_arg {
    int slot;
    err_t err;
};

static void rm_peer_cb(void *a)
{
    struct slot_arg *x = a;
    x->err = s_netif_ready ? wireguardif_remove_peer(&s_netif, (u8_t)x->slot) : ERR_IF;
}

static void connect_cb(void *a)
{
    struct slot_arg *x = a;
    x->err = s_netif_ready ? wireguardif_connect(&s_netif, (u8_t)x->slot) : ERR_IF;
}

static void up_cb(void *a)
{
    struct slot_arg *x = a;
    x->err = s_netif_ready ? wireguardif_peer_is_up(&s_netif, (u8_t)x->slot, NULL, NULL) : ERR_IF;
}

/* Runs fn for a WireGuard slot in the TCP/IP thread. ESP_OK if wireguardif returned ERR_OK. */
static esp_err_t slot_call(void (*fn)(void *), int slot)
{
    if (slot < 0 || slot >= WIREGUARD_MAX_PEERS) {
        return ESP_ERR_INVALID_ARG;
    }
    struct slot_arg a = {slot, ERR_ARG};
    if (tcpip_callback_wait(fn, &a) != ERR_OK) {
        return ESP_ERR_NO_MEM;
    }
    return a.err == ERR_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t nbl_wg_remove_peer(int slot)
{
    return slot_call(rm_peer_cb, slot);
}

esp_err_t nbl_wg_connect(int slot)
{
    return slot_call(connect_cb, slot);
}

bool nbl_wg_peer_up(int slot)
{
    return slot_call(up_cb, slot) == ESP_OK;
}

/* ---------------- Relay RX hand-over ---------------- */

struct rx_msg {
    int tag;
    size_t len;
    uint8_t data[];
};

static void rx_cb(void *a)
{
    struct rx_msg *m = a;
    if (s_netif_ready && s_netif.state) {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)m->len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, m->data, m->len);
            ip_addr_t from;
            IP_ADDR4(&from, 127, 0, 0, 1);
            wireguardif_network_rx(s_netif.state, NULL, p, &from, (u16_t)m->tag);
        } else {
            count(&s_rx_bad);
        }
    }
    atomic_fetch_sub(&s_rx_queued, sizeof(*m) + m->len);
    free(m);
}

void nbl_wg_rx(int tag, const uint8_t *pkt, size_t len)
{
    /* size check before malloc; len <= MTU + RX_OVERHEAD also keeps the u16_t pbuf size exact */
    if (len == 0 || len > atomic_load(&s_rx_max)) {
        count(&s_rx_bad);
        return;
    }
    size_t sz = sizeof(struct rx_msg) + len;
    struct rx_msg *m = NULL;
    if (atomic_fetch_add(&s_rx_queued, sz) + sz <= RX_QUEUE_MAX && (m = malloc(sz)) != NULL) {
        m->tag = tag;
        m->len = len;
        memcpy(m->data, pkt, len);
        /* never block the relay task: like a NIC, drop when the TCP/IP thread falls behind */
        if (tcpip_try_callback(rx_cb, m) == ERR_OK) {
            return;
        }
        free(m);
    }
    atomic_fetch_sub(&s_rx_queued, sz);
    count(&s_rx_bad);
}

void nbl_wg_stats(nbl_wg_stats_t *s)
{
    s->acl_drop = atomic_load(&s_acl_drop);
    s->acl_pass = atomic_load(&s_acl_pass);
    s->rx_bad = atomic_load(&s_rx_bad);
}
