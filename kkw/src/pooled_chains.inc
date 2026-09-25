/* Instantiated for the prover and verifier in circuits.c. All control flow and
 * memory access here depend only on public loop indices. Secret schedule bytes
 * are decoded into one-hot masks; they are never used as native array indices.
 * Keeping both evaluations in one template fixes their gate order together. */
#ifdef POOL_VERIFY
#define POOL_NAME(n) pool_v_##n
#define POOL_WORD mwv
#define POOL_PARTIES (N_PARTIES - 1)
#define POOL_CONST mwv_const
#define POOL_XOR mpc_XOR_v
#else
#define POOL_NAME(n) pool_##n
#define POOL_WORD mw
#define POOL_PARTIES N_PARTIES
#define POOL_CONST mw_const
#define POOL_XOR mpc_XOR
#endif

typedef struct {
    unsigned char **tapes;
    uint32_t *transcript;
    int *gc;
#ifdef POOL_VERIFY
    const uint32_t *aux, *msgs_e;
    int e;
#else
    uint32_t *aux;
#endif
} POOL_NAME(context);

static void POOL_NAME(and)(const POOL_WORD *x, const POOL_WORD *y, POOL_WORD *z,
                            POOL_NAME(context) *ctx)
{
#ifdef POOL_VERIFY
    mpc_AND_verify(x, y, z, ctx->tapes, ctx->e, ctx->msgs_e, ctx->aux,
                   ctx->transcript, ctx->gc);
#else
    mpc_AND(x, y, z, ctx->tapes, ctx->aux, ctx->transcript, ctx->gc);
#endif
}

static void POOL_NAME(add)(const POOL_WORD *x, const POOL_WORD *y, POOL_WORD *z,
                            POOL_NAME(context) *ctx)
{
#ifdef POOL_VERIFY
    mpc_ADD_verify(x, y, z, ctx->tapes, ctx->e, ctx->msgs_e, ctx->aux,
                   ctx->transcript, ctx->gc);
#else
    mpc_ADD(x, y, z, ctx->tapes, ctx->aux, ctx->transcript, ctx->gc);
#endif
}

static void POOL_NAME(or_into)(POOL_WORD *x, const POOL_WORD *y,
                                POOL_NAME(context) *ctx)
{
    POOL_WORD t;
    POOL_NAME(and)(x, y, &t, ctx);
    POOL_XOR(x, y, x);
    POOL_XOR(x, &t, x);
}

/* These bit operations are linear over XOR shares and require no MPC gates. */
static void POOL_NAME(bitmask)(const POOL_WORD *x, int bit, POOL_WORD *out)
{
    out->h = 0u - ((x->h >> bit) & 1u);
    for (int p = 0; p < POOL_PARTIES; p++)
        out->l[p] = 0u - ((x->l[p] >> bit) & 1u);
}

static uint32_t POOL_NAME(parity)(uint32_t x)
{
    x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; x ^= x >> 2; x ^= x >> 1;
    return x & 1u;
}

static void POOL_NAME(chains)(
    const unsigned char *d_pub, unsigned char *lam[POOL_PARTIES],
    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    const unsigned char mh_pub[32], unsigned char mh_lam[POOL_PARTIES][32],
    unsigned char *pkh_pub,
    unsigned char pkh_lam[POOL_PARTIES][XMSS_WOTS_LEN * XMSS_NODE_BYTES],
    POOL_WORD *check, POOL_NAME(context) *ctx)
{
    enum { GROUPS = (XMSS_WOTS_LEN + 3) / 4 };
    _Static_assert(XMSS_WOTS_LEN == 42 && XMSS_COORD_RES_BITS == 3 &&
                   XMSS_WOTS_MAX_STEPS == 7, "pooled selector parameter set");
    /* Four byte-sized positions per word. Even a malicious schedule increments
     * a position at most 99 times: 7 + 99 < 256, so no lane can wrap or carry
     * into its neighbor. Final equality to 7 therefore proves the exact number
     * of steps per chain, including zero steps for a digest coordinate of 7. */
    _Static_assert(XMSS_WOTS_MAX_STEPS + W_SCHEDULE_LEN < 256,
                   "packed position counters must not wrap");
    POOL_WORD nodes[XMSS_WOTS_LEN][XMSS_NODE_WORDS], positions[GROUPS];
    for (int g = 0; g < GROUPS; g++) POOL_CONST(0, &positions[g]);
    POOL_CONST(0, check);
    for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
        const int off = W_SIG_OFF + ci * XMSS_NODE_BYTES;
        for (int w = 0; w < XMSS_NODE_WORDS; w++) {
            nodes[ci][w].h = xmss_node_load_word(d_pub + off, (size_t)w);
            for (int p = 0; p < POOL_PARTIES; p++)
                nodes[ci][w].l[p] = xmss_node_load_word(lam[p] + off, (size_t)w);
        }
        const size_t pos = xmss_coord_bit_pos(ci);
        for (int b = 0; b < XMSS_COORD_RES_BITS; b++) {
            const int shift = 8 * (ci % 4) + b;
            positions[ci / 4].h ^= mh_bit(mh_pub, pos + b) << shift;
            for (int p = 0; p < POOL_PARTIES; p++)
                positions[ci / 4].l[p] ^= mh_bit(mh_lam[p], pos + b) << shift;
        }
    }

    for (int step = 0; step < W_SCHEDULE_LEN; step++) {
        POOL_WORD idx, onehot[2], masks[XMSS_WOTS_LEN], invalid;
        idx.h = d_pub[W_SCHEDULE_OFF + step];
        for (int p = 0; p < POOL_PARTIES; p++)
            idx.l[p] = lam[p][W_SCHEDULE_OFF + step];
        /* Each bit lane tests equality to one candidate index (all eight bits).
         * Two words cover indices 0..41; invalid bytes select no chain. */
        for (int g = 0; g < 2; g++) {
            for (int b = 0; b < 8; b++) {
                POOL_WORD match;
                POOL_NAME(bitmask)(&idx, b, &match);
                uint32_t pattern = 0;
                for (int lane = 0; lane < 32; lane++)
                    pattern |= (uint32_t)(1u ^ (((32 * g + lane) >> b) & 1u)) << lane;
                match.h ^= pattern;
                if (b == 0) onehot[g] = match;
                else POOL_NAME(and)(&onehot[g], &match, &onehot[g], ctx);
            }
        }
        onehot[1].h &= 0x3ffu;
        for (int p = 0; p < POOL_PARTIES; p++) onehot[1].l[p] &= 0x3ffu;
        invalid.h = POOL_NAME(parity)(onehot[0].h ^ onehot[1].h) ^ 1u;
        for (int p = 0; p < POOL_PARTIES; p++)
            invalid.l[p] = POOL_NAME(parity)(onehot[0].l[p] ^ onehot[1].l[p]);
        POOL_NAME(or_into)(check, &invalid, ctx);
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++)
            POOL_NAME(bitmask)(&onehot[ci / 32], ci % 32, &masks[ci]);

        POOL_WORD selected[XMSS_NODE_WORDS];
        for (int w = 0; w < XMSS_NODE_WORDS; w++) {
            POOL_CONST(0, &selected[w]);
            for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
                POOL_WORD t;
                POOL_NAME(and)(&masks[ci], &nodes[ci][w], &t, ctx);
                POOL_XOR(&selected[w], &t, &selected[w]);
            }
        }

        POOL_WORD position;
        POOL_CONST(0, &position);
        for (int g = 0; g < GROUPS; g++) {
            POOL_WORD increment, group_mask, t;
            POOL_CONST(0, &increment);
            POOL_CONST(0, &group_mask);
            for (int lane = 0; lane < 4 && 4 * g + lane < XMSS_WOTS_LEN; lane++) {
                const POOL_WORD *mask = &masks[4 * g + lane];
                increment.h ^= (mask->h & 1u) << (8 * lane);
                group_mask.h ^= mask->h;
                for (int p = 0; p < POOL_PARTIES; p++) {
                    increment.l[p] ^= (mask->l[p] & 1u) << (8 * lane);
                    group_mask.l[p] ^= mask->l[p];
                }
            }
            POOL_NAME(add)(&positions[g], &increment, &positions[g], ctx);
            POOL_NAME(and)(&group_mask, &positions[g], &t, ctx);
            POOL_XOR(&position, &t, &position);
        }
        /* Select the byte within the chosen group with two conditional shifts. */
        for (int b = 1; b >= 0; b--) {
            POOL_WORD delta, mask, t;
            const int shift = 8 << b;
            delta.h = position.h ^ (position.h >> shift);
            for (int p = 0; p < POOL_PARTIES; p++)
                delta.l[p] = position.l[p] ^ (position.l[p] >> shift);
            POOL_NAME(bitmask)(&idx, b, &mask);
            POOL_NAME(and)(&mask, &delta, &t, ctx);
            POOL_XOR(&position, &t, &position);
        }

        enum { TLEN = XMSS_PK_SEED_BYTES + XMSS_EPOCH_BYTES + 2 };
        unsigned char tw_pub[TLEN], twbuf[POOL_PARTIES][TLEN];
        unsigned char dom_pub[XMSS_NODE_BYTES + 1];
        unsigned char dombuf[POOL_PARTIES][XMSS_NODE_BYTES + 1];
        unsigned char h_pub[XMSS_NODE_BYTES], h_lam[POOL_PARTIES][XMSS_NODE_BYTES];
        unsigned char *tw_lam[POOL_PARTIES], *dom_lam[POOL_PARTIES], *out_lam[POOL_PARTIES];
        memcpy(tw_pub, pk_seed, XMSS_PK_SEED_BYTES);
        memcpy(tw_pub + XMSS_PK_SEED_BYTES, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        tw_pub[TLEN - 2] = (unsigned char)idx.h;
        tw_pub[TLEN - 1] = (unsigned char)position.h;
        dom_pub[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
        for (int p = 0; p < POOL_PARTIES; p++) {
            memset(twbuf[p], 0, XMSS_PK_SEED_BYTES);
            memcpy(twbuf[p] + XMSS_PK_SEED_BYTES, lam[p] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            twbuf[p][TLEN - 2] = (unsigned char)idx.l[p];
            twbuf[p][TLEN - 1] = (unsigned char)position.l[p];
            dombuf[p][XMSS_NODE_BYTES] = 0;
            tw_lam[p] = twbuf[p]; dom_lam[p] = dombuf[p]; out_lam[p] = h_lam[p];
        }
        for (int w = 0; w < XMSS_NODE_WORDS; w++) {
            xmss_node_store_word(dom_pub, (size_t)w, selected[w].h);
            for (int p = 0; p < POOL_PARTIES; p++)
                xmss_node_store_word(dombuf[p], (size_t)w, selected[w].l[p]);
        }
#ifdef POOL_VERIFY
        mpc_blake3_th_verify(dom_pub, dom_lam, XMSS_NODE_BYTES + 1,
                             tw_pub, tw_lam, TLEN, h_pub, out_lam, XMSS_NODE_BYTES,
                             ctx->tapes, ctx->e, ctx->msgs_e, ctx->aux,
                             ctx->transcript, ctx->gc);
#else
        mpc_blake3_th(dom_pub, dom_lam, XMSS_NODE_BYTES + 1,
                      tw_pub, tw_lam, TLEN, h_pub, out_lam, XMSS_NODE_BYTES,
                      ctx->tapes, ctx->aux, ctx->transcript, ctx->gc);
#endif
        for (int w = 0; w < XMSS_NODE_WORDS; w++) {
            POOL_WORD delta;
            delta.h = selected[w].h ^ xmss_node_load_word(h_pub, (size_t)w);
            for (int p = 0; p < POOL_PARTIES; p++)
                delta.l[p] = selected[w].l[p] ^ xmss_node_load_word(h_lam[p], (size_t)w);
            for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
                POOL_WORD t;
                POOL_NAME(and)(&masks[ci], &delta, &t, ctx);
                POOL_XOR(&nodes[ci][w], &t, &nodes[ci][w]);
            }
        }
    }
    for (int g = 0; g < GROUPS; g++) {
        for (int lane = 0; lane < 4 && 4 * g + lane < XMSS_WOTS_LEN; lane++)
            positions[g].h ^= (uint32_t)XMSS_WOTS_MAX_STEPS << (8 * lane);
        POOL_NAME(or_into)(check, &positions[g], ctx);
    }
    for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
        for (int w = 0; w < XMSS_NODE_WORDS; w++) {
            xmss_node_store_word(pkh_pub + ci * XMSS_NODE_BYTES, (size_t)w, nodes[ci][w].h);
            for (int p = 0; p < POOL_PARTIES; p++)
                xmss_node_store_word(pkh_lam[p] + ci * XMSS_NODE_BYTES, (size_t)w,
                                     nodes[ci][w].l[p]);
        }
    }
}

#undef POOL_NAME
#undef POOL_WORD
#undef POOL_PARTIES
#undef POOL_CONST
#undef POOL_XOR
