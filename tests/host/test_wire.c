// Host unit tests for the envelope decoder in nbl_wire.h: varint limits (10 bytes, 64 bits),
// lengths checked against the remaining input (64-bit lengths must not wrap), every wire type and
// truncated input. Plain C11, no ESP-IDF needed.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nbl_wire.h"

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

static size_t put_tag(uint8_t *b, size_t p, uint64_t field, unsigned wt)
{
    return p + nbl_put_varint(b + p, (field << 3) | wt);
}

static void test_varint(void)
{
    uint8_t b[16];
    uint64_t v;
    const uint64_t vals[] = {0, 1, 127, 128, 300, 16383, 16384, 65535, 4294967295ULL, 1ULL << 32,
                             0x7fffffffffffffffULL, 1ULL << 63, UINT64_MAX};
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        size_t n = nbl_put_varint(b, vals[i]);
        CHECK(n >= 1 && n <= 10);
        CHECK(nbl_get_varint(b, n, &v) == n && v == vals[i]);
        CHECK(nbl_get_varint(b, n - 1, &v) == 0); /* truncated */
    }
    /* the largest value takes exactly 10 bytes: 9 x 0xff, then 0x01 */
    CHECK(nbl_put_varint(b, UINT64_MAX) == 10 && b[9] == 0x01);
    /* a 10th byte above 1 does not fit into 64 bits */
    memset(b, 0xff, 9);
    for (unsigned last = 2; last < 0x80; last++) {
        b[9] = (uint8_t)last;
        CHECK(nbl_get_varint(b, 10, &v) == 0);
    }
    /* 11 bytes and more */
    memset(b, 0x80, 10);
    b[10] = 0;
    CHECK(nbl_get_varint(b, 11, &v) == 0);
    memset(b, 0xff, sizeof(b));
    CHECK(nbl_get_varint(b, sizeof(b), &v) == 0);
    b[9] = 0x81; /* continuation bit on the 10th byte */
    CHECK(nbl_get_varint(b, sizeof(b), &v) == 0);
    /* non-minimal but 10 bytes long: still valid */
    memset(b, 0x80, 9);
    b[9] = 0x00;
    CHECK(nbl_get_varint(b, 10, &v) == 10 && v == 0);
    CHECK(nbl_get_varint(b, 0, &v) == 0);
}

static void test_lengths(void)
{
    uint8_t b[64];
    const uint8_t *d;
    size_t dl, p;

    /* a field ending exactly at the end of the input is fine, one byte more is not */
    p = put_tag(b, 0, 1, 2);
    b[p++] = 3;
    memcpy(b + p, "abc", 3);
    p += 3;
    CHECK(nbl_get_bytes(b, p, 1, &d, &dl) == 0 && dl == 3 && d == b + 2);
    b[1] = 4;
    CHECK(nbl_get_bytes(b, p, 1, &d, &dl) != 0);
    /* zero length */
    b[1] = 0;
    CHECK(nbl_get_bytes(b, 2, 1, &d, &dl) == 0 && dl == 0);

    /* 64-bit lengths: "p + l" wrapped around in the old decoder. 2^64 - 11 brought p back to 0
     * (endless loop), others skipped backwards or past the end. Field 4 follows to be found. */
    const uint64_t huge[] = {UINT64_MAX, UINT64_MAX - 1, UINT64_MAX - 10, 1ULL << 63, 0xffffffffULL,
                             0x100000000ULL, (uint64_t)SIZE_MAX, (uint64_t)SIZE_MAX - 10, 64};
    for (size_t i = 0; i < sizeof(huge) / sizeof(huge[0]); i++) {
        p = put_tag(b, 0, 2, 2);
        p += nbl_put_varint(b + p, huge[i]);
        p = put_tag(b, p, 4, 2);
        b[p++] = 1;
        b[p++] = 'x';
        CHECK(nbl_get_bytes(b, p, 4, &d, &dl) != 0);
        CHECK(nbl_get_bytes(b, p, 2, &d, &dl) != 0);
    }
    /* length value with 11 bytes */
    p = put_tag(b, 0, 1, 2);
    memset(b + p, 0x80, 10);
    b[p + 10] = 0;
    CHECK(nbl_get_bytes(b, p + 11, 1, &d, &dl) != 0);
    /* length missing */
    p = put_tag(b, 0, 1, 2);
    CHECK(nbl_get_bytes(b, p, 1, &d, &dl) != 0);
    b[p] = 0x80; /* length varint cut off */
    CHECK(nbl_get_bytes(b, p + 1, 1, &d, &dl) != 0);
}

static void test_wire_types(void)
{
    uint8_t b[64];
    const uint8_t *d;
    size_t dl, p;
    const uint8_t want[] = {0x12, 0x02, 'o', 'k'}; /* field 2, "ok" */

    /* varint (0), 64-bit (1) and 32-bit (5) fields are skipped */
    p = put_tag(b, 0, 1, 0);
    p += nbl_put_varint(b + p, 300);
    p = put_tag(b, p, 3, 0);
    p += nbl_put_varint(b + p, UINT64_MAX); /* 10-byte varint value */
    p = put_tag(b, p, 5, 1);
    memset(b + p, 0xaa, 8);
    p += 8;
    p = put_tag(b, p, 6, 5);
    memset(b + p, 0xbb, 4);
    p += 4;
    memcpy(b + p, want, sizeof(want));
    p += sizeof(want);
    CHECK(nbl_get_bytes(b, p, 2, &d, &dl) == 0 && dl == 2 && !memcmp(d, "ok", 2));

    /* varint value with 11 bytes */
    p = put_tag(b, 0, 1, 0);
    memset(b + p, 0xff, 10);
    b[p + 10] = 0;
    p += 11;
    memcpy(b + p, want, sizeof(want));
    CHECK(nbl_get_bytes(b, p + sizeof(want), 2, &d, &dl) != 0);

    /* truncated fixed-size values */
    p = put_tag(b, 0, 1, 1);
    memset(b + p, 0, 7);
    CHECK(nbl_get_bytes(b, p + 7, 2, &d, &dl) != 0);
    p = put_tag(b, 0, 1, 5);
    memset(b + p, 0, 3);
    CHECK(nbl_get_bytes(b, p + 3, 2, &d, &dl) != 0);
    /* truncated varint value */
    p = put_tag(b, 0, 1, 0);
    b[p++] = 0x80;
    CHECK(nbl_get_bytes(b, p, 2, &d, &dl) != 0);

    /* groups (3, 4) and the invalid wire types 6 and 7 are rejected */
    for (unsigned wt = 3; wt <= 7; wt++) {
        if (wt == 5) {
            continue;
        }
        p = put_tag(b, 0, 1, wt);
        memcpy(b + p, want, sizeof(want));
        CHECK(nbl_get_bytes(b, p + sizeof(want), 2, &d, &dl) != 0);
    }
    /* field number 0 */
    b[0] = 0x02;
    b[1] = 0x00;
    memcpy(b + 2, want, sizeof(want));
    CHECK(nbl_get_bytes(b, 2 + sizeof(want), 2, &d, &dl) != 0);
    /* the largest field number is skipped like any other */
    p = put_tag(b, 0, (1u << 29) - 1, 2);
    b[p++] = 1;
    b[p++] = 'z';
    memcpy(b + p, want, sizeof(want));
    CHECK(nbl_get_bytes(b, p + sizeof(want), 2, &d, &dl) == 0 && dl == 2);
    CHECK(nbl_get_bytes(b, p + sizeof(want), (1 << 29) - 1, &d, &dl) == 0 && dl == 1 && d[0] == 'z');
    /* tag with 11 bytes, tag cut off */
    memset(b, 0x80, 10);
    b[10] = 0x01;
    CHECK(nbl_get_bytes(b, 11, 2, &d, &dl) != 0);
    b[0] = 0x80;
    CHECK(nbl_get_bytes(b, 1, 2, &d, &dl) != 0);
    CHECK(nbl_get_bytes(b, 0, 2, &d, &dl) != 0);
}

static void test_envelopes(void)
{
    uint8_t env[256];
    const uint8_t *d;
    size_t dl;
    const char *key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcde=";
    uint8_t body[100];
    for (size_t i = 0; i < sizeof(body); i++) {
        body[i] = (uint8_t)(i * 7);
    }
    /* management EncryptedMessage: wgPubKey=1, body=2, version=3 */
    size_t n = nbl_put_bytes(env, 0, 1, key, strlen(key));
    n = nbl_put_bytes(env, n, 2, body, sizeof(body));
    n = nbl_put_int(env, n, 3, 1);
    CHECK(nbl_get_bytes(env, n, 1, &d, &dl) == 0 && dl == strlen(key) && !memcmp(d, key, dl));
    CHECK(nbl_get_bytes(env, n, 2, &d, &dl) == 0 && dl == sizeof(body) && !memcmp(d, body, dl));
    CHECK(nbl_get_bytes(env, n, 3, &d, &dl) != 0); /* a varint, not length-delimited */
    /* signal EncryptedMessage: key=2, remoteKey=3, body=4 */
    size_t m = nbl_put_bytes(env, 0, 2, key, strlen(key));
    m = nbl_put_bytes(env, m, 3, key, strlen(key));
    m = nbl_put_bytes(env, m, 4, body, sizeof(body));
    CHECK(nbl_get_bytes(env, m, 4, &d, &dl) == 0 && dl == sizeof(body) && d + dl == env + m);
    /* every prefix of the message: either not found or a slice inside the prefix */
    for (size_t cut = 0; cut <= m; cut++) {
        for (int field = 1; field <= 5; field++) {
            if (nbl_get_bytes(env, cut, field, &d, &dl) == 0) {
                CHECK(d >= env && d + dl <= env + cut);
            }
        }
    }
    CHECK(nbl_get_bytes(env, m - 1, 4, &d, &dl) != 0);
}

int main(void)
{
    test_varint();
    test_lengths();
    test_wire_types();
    test_envelopes();
    printf("test_wire: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
