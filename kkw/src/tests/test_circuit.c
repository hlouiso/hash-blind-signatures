#include "../circuits.h"
#include "../shared.h"
#include "../xmss.h"
#include "../commitment.h"

#include "test_rng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    ASSERT_LIB_PARAMS();
    unsigned char sk_seed[32], pk_seed[XMSS_PK_SEED_BYTES];
    test_random_bytes(sk_seed, sizeof sk_seed);
    test_random_bytes(pk_seed, sizeof pk_seed);

    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, XMSS_TEST_H, root);

    unsigned char m_hat[32], r[HM_R_BYTES], a_mat[HM_A_BYTES];
    test_random_bytes(m_hat, sizeof m_hat);
    test_random_bytes(r, sizeof r);
    test_random_bytes(a_mat, sizeof a_mat);

    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, XMSS_TEST_H, 0, d, 32, &sig)) {
        printf("FAIL: native signing failed\n"); return 1;
    }
    if (!xmss_verify(pk_seed, root, d, 32, &sig)) {
        printf("FAIL: native signature does not verify\n"); return 1;
    }

    unsigned char input[W_END];
    memcpy(input + W_R_OFF,   r,      HM_R_BYTES);
    memcpy(input + W_A_OFF,   a_mat,  HM_A_BYTES);
    input[W_LEAFIDX_OFF+0] = 0; input[W_LEAFIDX_OFF+1] = 0;
    input[W_LEAFIDX_OFF+2] = 0; input[W_LEAFIDX_OFF+3] = 0;
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i*XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h*XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    unsigned char seeds[N_PARTIES][SEED_SIZE];
    test_random_bytes(seeds[0], N_PARTIES * SEED_SIZE);
    unsigned char *lam[N_PARTIES], *tapes[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        lam[p]   = malloc(INPUT_LEN);
        tapes[p] = malloc((size_t)TAPE_SIZE);
        if (!lam[p] || !tapes[p]) { printf("FAIL: OOM\n"); return 1; }
        expand_xshare(seeds[p], lam[p]);
        expand_tape(seeds[p], tapes[p]);
    }
    unsigned char *d_pub = malloc(INPUT_LEN);
    if (!d_pub) { printf("FAIL: OOM\n"); return 1; }
    memcpy(d_pub, input, INPUT_LEN);
    for (int p = 0; p < N_PARTIES; p++)
        for (int b = 0; b < INPUT_LEN; b++) d_pub[b] ^= lam[p][b];

    int YBIG = 300000;
    uint32_t *aux = calloc((size_t)YBIG, sizeof(uint32_t));
    uint32_t *s_all = calloc((size_t)N_PARTIES * YBIG, sizeof(uint32_t));
    if (!aux || !s_all) { printf("FAIL: OOM\n"); return 1; }

    unsigned char r_j[32];
    test_random_bytes(r_j, 32);
    a A;
    uint32_t zh[8];
    building_views(&A, m_hat, pk_seed, d_pub, lam, tapes, aux, s_all, r_j, zh);

    unsigned char circ_root[XMSS_NODE_BYTES];
    uint32_t circ_sum;
    for (int w = 0; w < YP_ROOT_WORDS; w++) {
        uint32_t v = zh[w];
        for (int p = 0; p < N_PARTIES; p++) v ^= A.yp[p][w];
        xmss_node_store_word(circ_root, (size_t)w, v);
    }
    circ_sum = zh[YP_SUM_WORD];
    for (int p = 0; p < N_PARTIES; p++) circ_sum ^= A.yp[p][YP_SUM_WORD];
    uint32_t circ_leftover = zh[YP_LEFTOVER_WORD];
    for (int p = 0; p < N_PARTIES; p++) circ_leftover ^= A.yp[p][YP_LEFTOVER_WORD];

    int ok_root = (memcmp(circ_root, root, XMSS_NODE_BYTES) == 0);
    int ok_sum  = (circ_sum == (uint32_t)XMSS_TARGET_SUM);
    int ok_left = (circ_leftover == 0);

    printf("  circuit root  %s native root\n", ok_root ? "==" : "!=  MISMATCH");
    printf("  circuit sum   = %u (target %d) %s\n", circ_sum, XMSS_TARGET_SUM, ok_sum ? "ok" : "MISMATCH");
    printf("  leftover bits = %u (must be 0) %s\n", circ_leftover, ok_left ? "ok" : "MISMATCH");
    printf("  gate count = %d  -> set ySize=%d in shared.c\n", g_circuit_gates, g_circuit_gates);

    for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tapes[p]); }
    free(aux); free(s_all); free(d_pub);

    if (ok_root && ok_sum && ok_left) { printf("\nCIRCUIT OK\n"); return 0; }
    printf("\nCIRCUIT FAILED\n"); return 1;
}
