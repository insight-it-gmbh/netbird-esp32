// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NBL_KEY_LEN 32
#define NBL_KEY_B64 44      /* base64 of a 32-byte key, without NUL */
#define NBL_RELAY_ID_LEN 36 /* "sha-" + sha256 */

/* NVS: namespace "nbl" holds the device key and the registration flag (u8 1 = the management
 * server accepted this key once, the setup key is no longer sent). */
#define NBL_NVS_NS "nbl"
#define NBL_NVS_KEY "wgkey"
#define NBL_NVS_REG "reg"

void nbl_random(void *buf, size_t n);

int nbl_b64_enc(const uint8_t *in, size_t n, char *out, size_t cap); /* NUL-terminated; length or -1 */
int nbl_b64_dec(const char *in, uint8_t *out, size_t cap);           /* length or -1 */

/** Loads the WireGuard private key from NVS. Only if none is stored (ESP_ERR_NVS_NOT_FOUND) a new
 *  one is generated (CONFIG_NBL_KEYGEN_ENTROPY_SOURCE: with the SAR ADC entropy source enabled)
 *  and stored, after the registration flag has been erased. Any other NVS error, or a stored key of
 *  the wrong size, is returned unchanged: the identity is never replaced silently.
 *  Returns ESP_OK (0) or an esp_err_t code; *created = 1 for a new key. */
int nbl_keys_load_or_create(uint8_t priv[NBL_KEY_LEN], uint8_t pub[NBL_KEY_LEN], int *created);
void nbl_keys_erase(void);

/** NaCl box (curve25519 + xsalsa20 + poly1305) with a precomputed shared key. */
int nbl_box_precompute(uint8_t shared[32], const uint8_t their_pub[32], const uint8_t my_priv[32]);
/** out must hold len + 40 bytes: nonce(24) | mac(16) | ciphertext. Returns the total length or -1. */
int nbl_box_seal(uint8_t *out, const uint8_t shared[32], const uint8_t *msg, size_t len);
/** Opens box = nonce(24) | mac(16) | ciphertext in place, without another buffer: on success the
 *  plaintext (len - 40 bytes) starts at box + 40 and its length is returned. The first 40 bytes of
 *  box are overwritten in any case. Returns -1 if len < 40 or the authentication fails. */
int nbl_box_open_inplace(uint8_t *box, size_t len, const uint8_t shared[32]);

/** Relay peer ID: "sha-" + SHA256(key as base64 text). */
void nbl_relay_id(const char *key_b64, uint8_t out[NBL_RELAY_ID_LEN]);

#ifdef __cplusplus
}
#endif
