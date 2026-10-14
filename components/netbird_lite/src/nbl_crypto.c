// SPDX-License-Identifier: Apache-2.0
#include "nbl_crypto.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "tweetnacl.h"
#if CONFIG_NBL_KEYGEN_ENTROPY_SOURCE
#include "bootloader_random.h"
#endif

static const char *TAG = "nbl_crypto";

/* required by tweetnacl.c */
void randombytes(unsigned char *p, unsigned long long n)
{
    esp_fill_random(p, (size_t)n);
}

void nbl_random(void *buf, size_t n)
{
    esp_fill_random(buf, n);
}

int nbl_b64_enc(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char *)out, cap, &olen, in, n) != 0 || olen >= cap) {
        return -1;
    }
    out[olen] = 0;
    return (int)olen;
}

int nbl_b64_dec(const char *in, uint8_t *out, size_t cap)
{
    size_t olen = 0;
    if (mbedtls_base64_decode(out, cap, &olen, (const unsigned char *)in, strlen(in)) != 0) {
        return -1;
    }
    return (int)olen;
}

/* esp_fill_random() only yields true random numbers while Wi-Fi/Bluetooth runs or an entropy
 * source is enabled (CONFIG_NBL_KEYGEN_ENTROPY_SOURCE, for Ethernet-only boards). */
static void keygen(uint8_t priv[NBL_KEY_LEN])
{
#if CONFIG_NBL_KEYGEN_ENTROPY_SOURCE
    bootloader_random_enable();
#endif
    esp_fill_random(priv, NBL_KEY_LEN);
#if CONFIG_NBL_KEYGEN_ENTROPY_SOURCE
    bootloader_random_disable();
#endif
    priv[0] &= 248;
    priv[31] = (priv[31] & 127) | 64;
}

int nbl_keys_load_or_create(uint8_t priv[NBL_KEY_LEN], uint8_t pub[NBL_KEY_LEN], int *created)
{
    *created = 0;
    nvs_handle_t nvs;
    esp_err_t e = nvs_open(NBL_NVS_NS, NVS_READWRITE, &nvs);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "NVS not available (%s): nvs_flash_init() not called?", esp_err_to_name(e));
        return e;
    }
    size_t sz = NBL_KEY_LEN;
    e = nvs_get_blob(nvs, NBL_NVS_KEY, priv, &sz);
    if (e == ESP_OK && sz != NBL_KEY_LEN) {
        e = ESP_ERR_NVS_INVALID_LENGTH;
    }
    if (e == ESP_ERR_NVS_NOT_FOUND) {
        /* First start: no identity yet. The registration flag goes first, so that a power loss
         * can never leave a flag that belongs to a different key. */
        e = nvs_erase_key(nvs, NBL_NVS_REG);
        if (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) {
            e = nvs_commit(nvs);
        }
        if (e == ESP_OK) {
            keygen(priv);
            e = nvs_set_blob(nvs, NBL_NVS_KEY, priv, NBL_KEY_LEN);
        }
        if (e == ESP_OK) {
            e = nvs_commit(nvs);
        }
        *created = e == ESP_OK;
    } else if (e != ESP_OK) {
        ESP_LOGE(TAG, "Stored device key unreadable (%s): not replaced", esp_err_to_name(e));
    }
    nvs_close(nvs);
    if (e != ESP_OK) {
        memset(priv, 0, NBL_KEY_LEN);
        *created = 0;
        return e;
    }
    crypto_scalarmult_base(pub, priv);
    return ESP_OK;
}

void nbl_keys_erase(void)
{
    nvs_handle_t nvs;
    if (nvs_open(NBL_NVS_NS, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

int nbl_box_precompute(uint8_t shared[32], const uint8_t their_pub[32], const uint8_t my_priv[32])
{
    return crypto_box_beforenm(shared, their_pub, my_priv) == 0 ? 0 : -1;
}

int nbl_box_seal(uint8_t *out, const uint8_t shared[32], const uint8_t *msg, size_t len)
{
    /* tweetnacl API: the input starts with 32 zero bytes, the output starts with 16 zero bytes */
    size_t tmp = len + 32;
    uint8_t *m = calloc(1, tmp);
    uint8_t *c = calloc(1, tmp);
    if (!m || !c) {
        free(m);
        free(c);
        return -1;
    }
    memcpy(m + 32, msg, len);
    uint8_t nonce[24];
    esp_fill_random(nonce, sizeof(nonce));
    int rc = crypto_box_afternm(c, m, tmp, nonce, shared);
    if (rc == 0) {
        memcpy(out, nonce, 24);
        memcpy(out + 24, c + 16, len + 16); /* mac(16) | ciphertext */
    }
    free(m);
    free(c);
    return rc == 0 ? (int)(len + 40) : -1;
}

int nbl_box_open_inplace(uint8_t *box, size_t len, const uint8_t shared[32])
{
    if (len < 40) {
        return -1;
    }
    /* tweetnacl opens c = 16 zero bytes | mac | ciphertext into m = 32 zero bytes | plaintext,
     * and m may equal c (it verifies the MAC first, then XORs byte by byte). Starting c 8 bytes
     * into the box puts mac and ciphertext where they already are; the 16 bytes in front of the
     * mac are the end of the nonce, which is copied out first. */
    uint8_t nonce[24];
    memcpy(nonce, box, sizeof(nonce));
    uint8_t *c = box + 8;
    memset(c, 0, 16);
    if (crypto_box_open_afternm(c, c, len - 8, nonce, shared) != 0) {
        return -1;
    }
    return (int)(len - 40);
}

void nbl_relay_id(const char *key_b64, uint8_t out[NBL_RELAY_ID_LEN])
{
    memcpy(out, "sha-", 4);
    mbedtls_sha256((const unsigned char *)key_b64, strlen(key_b64), out + 4, 0);
}
