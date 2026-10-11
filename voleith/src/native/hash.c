#include "hash.h"
#include <KeccakHash.h>
#include <stdlib.h>

static void absorb(Keccak_HashInstance *h, const void *p, size_t n) {
    if (n && Keccak_HashUpdate(h, p, n * 8) != KECCAK_SUCCESS) abort();
}
static void squeeze(Keccak_HashInstance *h, void *out, size_t n) {
    if (Keccak_HashFinal(h, NULL) != KECCAK_SUCCESS ||
        Keccak_HashSqueeze(h, out, n * 8) != KECCAK_SUCCESS) abort();
}
void shake256_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
    Keccak_HashInstance h;
    Keccak_HashInitialize_SHAKE256(&h);
    absorb(&h, data, len);
    squeeze(&h, out, out_len);
}
void shake_th(const uint8_t *domain, size_t domain_len, const uint8_t *data,
              size_t data_len, uint8_t *out, size_t out_len) {
    if (domain_len > 255) abort();
    const uint8_t n = (uint8_t)domain_len;
    Keccak_HashInstance h;
    Keccak_HashInitialize_SHAKE256(&h);
    absorb(&h, SHAKE_APP_PREFIX, SHAKE_APP_PREFIX_BYTES);
    absorb(&h, &n, 1);
    absorb(&h, domain, domain_len);
    absorb(&h, data, data_len);
    squeeze(&h, out, out_len);
}
void shake_keyed_xof(const uint8_t key[32], uint8_t domain,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len) {
    /* Fixed-length secret prefix; the native signature assumes this is a PRF. */
    Keccak_HashInstance h;
    Keccak_HashInitialize_SHAKE256(&h);
    absorb(&h, "HBS-VOLE-PRF-v1", 15);
    absorb(&h, &domain, 1);
    absorb(&h, key, 32);
    absorb(&h, data, data_len);
    squeeze(&h, out, out_len);
}
