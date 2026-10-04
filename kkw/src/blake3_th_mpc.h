#ifndef BLIND_MSS_BLAKE3_TH_MPC_H
#define BLIND_MSS_BLAKE3_TH_MPC_H

#include "blake3_th.h"

/* Circuit inputs have public sizes. Larger messages require BLAKE3's chunk
 * tree and are rejected rather than evaluated as a nonstandard hash. */
static inline int blake3_th_mpc_valid_sizes(int dom_len, int data_len, int out_len)
{
    return dom_len >= 0 && dom_len <= BLAKE3_TH_MAX_DOMAIN &&
           data_len >= 0 && data_len <= BLAKE3_CHUNK_LEN - BLAKE3_TH_FRAME_LEN - dom_len &&
           out_len >= 0 && out_len <= BLAKE3_OUT_LEN;
}

/* Load LE32(domain_len) || domain || data, with zero padding. The length
 * prefix is public, so its mask shares are zero. No access depends on secrets. */
static inline uint32_t blake3_th_mpc_word(const unsigned char *domain, int dom_len,
                                        const unsigned char *data, int data_len,
                                        int off, int mask_share)
{
    uint32_t word = 0;
    for (int b = 0; b < 4; b++) {
        const int i = off + b;
        unsigned char byte = 0;
        if (i < BLAKE3_TH_FRAME_LEN) {
            if (!mask_share) byte = (unsigned char)((uint32_t)dom_len >> (8 * i));
        } else if (i < BLAKE3_TH_FRAME_LEN + dom_len) {
            if (domain) byte = domain[i - BLAKE3_TH_FRAME_LEN];
        } else {
            const int j = i - BLAKE3_TH_FRAME_LEN - dom_len;
            if (data && j < data_len) byte = data[j];
        }
        word |= (uint32_t)byte << (8 * b);
    }
    return word;
}

#endif
