#ifndef VOLEITH_NATIVE_SLH_COMMIT_H
#define VOLEITH_NATIVE_SLH_COMMIT_H

/* The Halevi–Micali commitment of commitment.h with SHAKE256 tag blocks, for
 * the SLH-DSA-SHAKE blind signature. The XMSS path keeps commitment.h.
 *
 *   m_hat = SHAKE256(TAG_MESSAGE || msg, 256)
 *   y     = SHAKE256(TAG_NONCE   || r,   256)
 *   d     = SHAKE256(TAG_DIGEST  || a || b || y, 256), the message signed.
 *
 * A tag block is an ASCII label padded with 0xFF to the SHAKE256 rate, 136
 * bytes, the analogue of binius64/src/slh/commit.rs's 64-byte SHA-256 tag
 * blocks: the sponge state after absorbing it is a constant, so the circuit
 * starts from that state and pays nothing for the tag. (A 64-byte tag would
 * share its first permutation with data and cost one extra permutation for
 * y and one for d.)
 *
 * Domain separation. Every other SHAKE256 input of the scheme has a fixed
 * structure that no tagged input shares:
 * - SLH-DSA's F, H, T_l and PRF hash PK.seed || ADRS || ...: input bytes
 *   16..18 are the top bytes of the layer address (< 256), and bytes 20..23
 *   the top four bytes of the 12-byte tree address (the tree index is below
 *   2^64), so all are 0. Each tag has nonzero bytes in both ranges.
 * - SLH-DSA's H_msg hashes R || PK.seed || PK.root || 0x00 || 0x00 || d
 *   (pure signing, empty context): bytes 48..49 are 0, a tag's are 0xFF.
 * - SLH-DSA's PRF_msg hashes SK.prf || opt_rand || 0x00 || 0x00 || d:
 *   bytes 32..33 are 0, a tag's are label characters.
 * - VOLEitH's Fiat–Shamir transcript (proof.cpp, slh_proof.cpp) starts every
 *   input with the ASCII string "HBS-VOLE-", a tag with "blind-".
 * - FAEST's GGM leaf hash and the VOLE check use SHAKE128 or the transcript
 *   states above; the XMSS application hashes start with "HBS-VOLE-v1".
 * slh_commit_test checks these byte positions. */

#include <stddef.h>
#include <stdint.h>

#include "commitment.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLH_TAG_BYTES 136

extern const uint8_t SLH_TAG_MESSAGE[SLH_TAG_BYTES]; /* blind-slh-dsa/shake256/v1/message-hash */
extern const uint8_t SLH_TAG_NONCE[SLH_TAG_BYTES];   /* blind-slh-dsa/shake256/v1/commitment-y */
extern const uint8_t SLH_TAG_DIGEST[SLH_TAG_BYTES];  /* blind-slh-dsa/shake256/v1/commitment-d */

/* The Keccak-f[1600] state after absorbing a tag block. */
void slh_tag_state(const uint8_t tag[SLH_TAG_BYTES], uint64_t state[25]);

void slh_message_hash(const uint8_t *msg, size_t len, uint8_t m_hat[32]);
void slh_nonce_hash(const uint8_t r[HM_R_BYTES], uint8_t y[HM_Y_BYTES]);
void slh_com_digest(const uint8_t com[HM_COM_BYTES], uint8_t d[32]);
/* com = a || b || y with b_k = m_hat_k + sum_i a_{k,i} r_i, and d. */
void slh_hm_commit(const uint8_t m_hat[32], const uint8_t r[HM_R_BYTES],
                   const uint8_t a[HM_A_BYTES], uint8_t com[HM_COM_BYTES],
                   uint8_t d[32]);

#ifdef __cplusplus
}
#endif
#endif
