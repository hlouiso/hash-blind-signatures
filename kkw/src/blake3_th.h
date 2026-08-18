#ifndef BLIND_MSS_BLAKE3_TH_H
#define BLIND_MSS_BLAKE3_TH_H

/* Tweakable hash built from raw BLAKE3 compression. The domain (at most 28
 * bytes) is zero-padded into the chaining value and its length occupies cv[7].
 * Data is zero-padded by the compression interface and the final block sets
 * ROOT; this is not the standard BLAKE3 hash function. */

#include <stddef.h>
#include <stdint.h>

void blake3_compress(const uint32_t cv[8], const uint32_t block_words[16],
                     uint64_t counter, uint32_t block_len, uint32_t flags,
                     uint32_t out[8]);

#define BLAKE3_CHUNK_START (1u << 0)
#define BLAKE3_CHUNK_END   (1u << 1)
#define BLAKE3_ROOT        (1u << 3)

void blake3_th(const uint8_t *domain, size_t domain_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out, size_t out_len);

typedef struct {
    uint32_t cv[8];
    uint8_t buf[64];
    size_t buflen;
    int poisoned;
} blake3_th_ctx;

void blake3_th_init(blake3_th_ctx *ctx, const uint8_t *domain, size_t domain_len);
void blake3_th_update(blake3_th_ctx *ctx, const void *data, size_t len);
void blake3_th_final(blake3_th_ctx *ctx, uint8_t *out, size_t out_len);

#endif
