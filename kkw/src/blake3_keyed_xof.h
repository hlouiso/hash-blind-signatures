#ifndef BLIND_MSS_BLAKE3_KEYED_XOF_H
#define BLIND_MSS_BLAKE3_KEYED_XOF_H

/* Full keyed BLAKE3 with length-framed, disjoint domains for non-arithmetized
 * seed expansion. */

#include <stddef.h>
#include <stdint.h>

#define BLIND_MSS_BLAKE3_KEY_LEN 32

#define BLAKE3_XOF_DOM_KKW_TAPE       "blind-mss KKW tape expansion v1"
#define BLAKE3_XOF_DOM_KKW_SEEDS      "blind-mss KKW party-seed expansion v1"
#define BLAKE3_XOF_DOM_KKW_XSHARE     "blind-mss KKW witness-mask expansion v1"
#define BLAKE3_XOF_DOM_XMSS_WOTS_SK   "blind-mss XMSS WOTS secret-key expansion v1"
#define BLAKE3_XOF_DOM_XMSS_UPPER     "blind-mss XMSS upper-sibling expansion v1"

void blake3_keyed_xof(const uint8_t key[BLIND_MSS_BLAKE3_KEY_LEN],
                      const char *domain,
                      const void *input, size_t input_len,
                      uint8_t *out, size_t out_len);

#endif
