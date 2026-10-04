#ifndef BLIND_MSS_BLAKE3_TH_H
#define BLIND_MSS_BLAKE3_TH_H

/* Standard BLAKE3 derive-key mode with the fixed context below, hashing
 * LE32(domain_len) || domain || data. Domains are at most 28 bytes and output
 * is at most 32 bytes. Native hashing supports arbitrary message lengths;
 * the MPC gadget supports framed messages fitting in one BLAKE3 chunk.
 * These v2 hashes are incompatible with the former raw-compression mode. */

#include <blake3.h>
#include <stddef.h>
#include <stdint.h>

#define BLAKE3_TH_CONTEXT "blind-mss tweakable hash v2"
#define BLAKE3_TH_MAX_DOMAIN 28
#define BLAKE3_TH_FRAME_LEN 4

/* BLAKE3's context key for BLAKE3_TH_CONTEXT; tested against the upstream API. */
extern const uint32_t blake3_th_context_key[8];

void blake3_compress(const uint32_t cv[8], const uint32_t block_words[16],
                     uint64_t counter, uint32_t block_len, uint32_t flags,
                     uint32_t out[8]);

#define BLAKE3_CHUNK_START (1u << 0)
#define BLAKE3_CHUNK_END   (1u << 1)
#define BLAKE3_ROOT        (1u << 3)
#define BLAKE3_DERIVE_KEY_MATERIAL (1u << 6)

/* Return 1 on success, 0 on invalid input. Failure leaves output untouched. */
int blake3_th(const uint8_t *domain, size_t domain_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out, size_t out_len);

typedef struct {
    blake3_hasher hasher;
    int poisoned;
} blake3_th_ctx;

int blake3_th_init(blake3_th_ctx *ctx, const uint8_t *domain, size_t domain_len);
int blake3_th_update(blake3_th_ctx *ctx, const void *data, size_t len);
int blake3_th_final(const blake3_th_ctx *ctx, uint8_t *out, size_t out_len);

#endif
