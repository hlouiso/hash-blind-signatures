#ifndef BUILDING_H
#define BUILDING_H

#include "commitment.h"
#include "shared.h"
#include "xmss.h"

#include <stdbool.h>

/* Secret witness: r || a || leaf_index || nonce || WOTS tips || auth path || schedule. */
#define W_R_OFF 0
#define W_R_LEN HM_R_BYTES
#define W_A_OFF (W_R_OFF + W_R_LEN)
#define W_A_LEN HM_A_BYTES
#define W_LEAFIDX_OFF (W_A_OFF + W_A_LEN)
#define W_LEAFIDX_LEN 4
#define W_NONCE_OFF (W_LEAFIDX_OFF + W_LEAFIDX_LEN)
#define W_SIG_OFF (W_NONCE_OFF + XMSS_NONCE_LEN)
#define W_SIG_LEN (XMSS_WOTS_LEN * XMSS_NODE_BYTES)
#define W_PATH_OFF (W_SIG_OFF + W_SIG_LEN)
#define W_PATH_LEN (XMSS_H * XMSS_NODE_BYTES)
#define W_SCHEDULE_OFF (W_PATH_OFF + W_PATH_LEN)
#define W_SCHEDULE_LEN (XMSS_WOTS_LEN * XMSS_WOTS_MAX_STEPS - XMSS_TARGET_SUM)
#define W_END (W_SCHEDULE_OFF + W_SCHEDULE_LEN)

_Static_assert(W_SCHEDULE_LEN == 99, "pooled circuit gate count assumes 99 steps");
_Static_assert(W_END == 1599, "witness layout changed: recheck the circuit gate count");

#define YP_ROOT_WORDS XMSS_NODE_WORDS
/* Public output also binds the target-sum and the two unused digest bits. */
#define YP_SUM_WORD YP_ROOT_WORDS
#define YP_LEFTOVER_WORD (YP_SUM_WORD + 1)
/* Must be zero: schedule indices are valid and every chain ends at position 7. */
#define YP_POOL_WORD (YP_LEFTOVER_WORD + 1)
_Static_assert(YP_POOL_WORD < 8, "public output no longer fits in eight words");

extern int g_circuit_gates;

/* Append the honest private schedule to an otherwise populated witness.
 * Returns 1 on success, 0 if the message digest fails the encoding checks. */
int kkw_build_schedule(unsigned char input[W_END], const unsigned char m_hat[32],
                       const unsigned char pk_seed[XMSS_PK_SEED_BYTES]);

void building_views(a *a, const unsigned char message_digest[32],
                    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                    const unsigned char *d_pub,
                    unsigned char *lam[N_PARTIES],
                    unsigned char *tapes[N_PARTIES],
                    uint32_t *aux, uint32_t *s_all,
                    const unsigned char *r_j, uint32_t zh_out[8]);

void verify(const unsigned char message_digest[32],
            const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
            bool *error, a *a, int e, z *z, uint32_t zh_out[8]);

#endif
