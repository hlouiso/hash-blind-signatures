#include "../circuits.h"
#include "../MPC_prove_functions.h"
#include "test_rng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t mh_bit(const unsigned char *buf, size_t bit)
{
    return (uint32_t)((buf[bit / 8] >> (bit % 8)) & 1u);
}

/* Exercise the actual pooled subcircuit with chosen digest coordinates. This
 * covers every chain length without relying on nonce grinding to hit them. */
#include "../pooled_chains.inc"

static unsigned char input[W_END], d_pub[W_END];
static unsigned char mh[32], mh_pub[32], mh_lam[N_PARTIES][32];
static unsigned char pk_seed[XMSS_PK_SEED_BYTES];
static unsigned char *lam[N_PARTIES], *tapes[N_PARTIES];
static unsigned char schedule[W_SCHEDULE_LEN];
static xmss_node expected[XMSS_WOTS_LEN];
static uint32_t *aux;
static int failures;

static void run_case(const char *label, int accept)
{
    memcpy(d_pub, input, W_END);
    for (int p = 0; p < N_PARTIES; p++)
        for (int b = 0; b < W_END; b++) d_pub[b] ^= lam[p][b];
    unsigned char pkh_pub[XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    unsigned char pkh_lam[N_PARTIES][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    mw check;
    int gc = 0;
    pool_context ctx = { .tapes = tapes, .transcript = NULL, .gc = &gc, .aux = aux };
    pool_chains(d_pub, lam, pk_seed, mh_pub, mh_lam, pkh_pub, pkh_lam, &check, &ctx);
    uint32_t bad = check.h;
    for (int p = 0; p < N_PARTIES; p++) bad ^= check.l[p];
    int ok = ((bad == 0) == accept) && gc == 70400;
    if (accept) {
        for (int p = 0; p < N_PARTIES; p++)
            for (size_t b = 0; b < sizeof pkh_pub; b++) pkh_pub[b] ^= pkh_lam[p][b];
        ok &= memcmp(pkh_pub, expected, sizeof expected) == 0;
    }
    if (!ok) { fprintf(stderr, "FAIL: %s (pool=%u, gates=%d)\n", label, bad, gc); failures++; }
}

int main(void)
{
    ASSERT_LIB_PARAMS();
    test_random_bytes(input, sizeof input);
    test_random_bytes(pk_seed, sizeof pk_seed);
    /* Digits 0..7, followed by three 4s and thirty-one 5s: total 195.
     * Thus all eight chain lengths and all 42 indices occur across the tests. */
    int coords[XMSS_WOTS_LEN], slot = 0;
    for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
        coords[ci] = ci < 8 ? ci : ci < 11 ? 4 : 5;
        const size_t bit = xmss_coord_bit_pos(ci);
        for (int b = 0; b < XMSS_COORD_RES_BITS; b++)
            mh[(bit + b) / 8] |= ((coords[ci] >> b) & 1u) << ((bit + b) % 8);
        for (int pos = coords[ci]; pos < XMSS_WOTS_MAX_STEPS; pos++)
            schedule[slot++] = (unsigned char)ci;
    }
    if (slot != W_SCHEDULE_LEN) return 1;
    uint32_t epoch = 0;
    for (int b = 0; b < XMSS_EPOCH_BYTES; b++)
        epoch = (epoch << 8) | input[W_LEAFIDX_OFF + b];
    for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
        memcpy(expected[ci], input + W_SIG_OFF + ci * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
        for (int pos = coords[ci] + 1; pos <= XMSS_WOTS_MAX_STEPS; pos++) {
            xmss_node next;
            xmss_hash_chain_step(pk_seed, epoch, expected[ci], (uint8_t)ci, (uint8_t)pos, next);
            memcpy(expected[ci], next, XMSS_NODE_BYTES);
        }
    }
    aux = malloc((size_t)ySize * sizeof *aux);
    if (!aux) return 1;
    memcpy(mh_pub, mh, sizeof mh);
    for (int p = 0; p < N_PARTIES; p++) {
        unsigned char seed[SEED_SIZE];
        test_random_bytes(seed, sizeof seed);
        lam[p] = malloc(W_END); tapes[p] = malloc((size_t)TAPE_SIZE);
        if (!lam[p] || !tapes[p]) return 1;
        expand_xshare(seed, lam[p]); expand_tape(seed, tapes[p]);
        test_random_bytes(mh_lam[p], sizeof mh_lam[p]);
        for (int b = 0; b < 32; b++) mh_pub[b] ^= mh_lam[p][b];
    }
    memcpy(input + W_SCHEDULE_OFF, schedule, sizeof schedule);
    run_case("ascending schedule, native endpoints", 1);
    for (int i = 0; i < W_SCHEDULE_LEN; i++)
        input[W_SCHEDULE_OFF + i] = schedule[W_SCHEDULE_LEN - 1 - i];
    run_case("descending schedule, native endpoints", 1);
    for (int i = 0; i < W_SCHEDULE_LEN; i++)
        input[W_SCHEDULE_OFF + i] = schedule[(37 * i) % W_SCHEDULE_LEN];
    run_case("interleaved schedule, native endpoints", 1);

    /* Every possible byte replacing the first step: only the original index
     * is valid. This includes all illegal indices and each possible wrong chain,
     * especially 31/32 and 39/40 at word/group boundaries, and the completed 7. */
    memcpy(input + W_SCHEDULE_OFF, schedule, sizeof schedule);
    for (int idx = 0; idx < 256; idx++) {
        char label[64];
        snprintf(label, sizeof label, "first step selects index %d", idx);
        input[W_SCHEDULE_OFF] = (unsigned char)idx;
        run_case(label, idx == schedule[0]);
    }
    memset(input + W_SCHEDULE_OFF, 0, W_SCHEDULE_LEN);
    run_case("99 advances of one chain cannot wrap packed positions", 0);
    memset(input + W_SCHEDULE_OFF, 7, W_SCHEDULE_LEN);
    run_case("99 advances of an already complete chain", 0);
    memset(input + W_SCHEDULE_OFF, 255, W_SCHEDULE_LEN);
    run_case("invalid-index errors do not cancel", 0);
    for (int p = 0; p < N_PARTIES; p++) { free(lam[p]); free(tapes[p]); }
    free(aux);
    printf("Pooled chain checks: %s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures != 0;
}
