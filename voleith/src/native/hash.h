#ifndef VOLEITH_NATIVE_HASH_H
#define VOLEITH_NATIVE_HASH_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SHAKE_APP_PREFIX "HBS-VOLE-v1"
#define SHAKE_APP_PREFIX_BYTES 11
#define SHAKE_PRG_WOTS 1
#define SHAKE_PRG_UPPER 2
void shake_th(const uint8_t *domain, size_t domain_len, const uint8_t *data,
              size_t data_len, uint8_t *out, size_t out_len);
void shake_keyed_xof(const uint8_t key[32], uint8_t domain,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len);
void shake256_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);
#ifdef __cplusplus
}
#endif
#endif
