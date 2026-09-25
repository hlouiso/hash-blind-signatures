#include "circuits.h"
#include "MPC_prove_functions.h"
#include "MPC_verify_functions.h"
#include "commitment.h"
#include "gf128.h"
#include "shared.h"
#include "xmss.h"

#include <omp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_circuit_gates = 0;

static const unsigned char HM_DOM_Y[3] = {'H', 'M', 'y'};
static const unsigned char HM_DOM_D[3] = {'H', 'M', 'd'};

static uint32_t mh_bit(const unsigned char *buf, size_t j)
{
    return (uint32_t)((buf[j / 8] >> (j % 8)) & 1u);
}

#include "pooled_chains.inc"
#define POOL_VERIFY
#include "pooled_chains.inc"
#undef POOL_VERIFY

int kkw_build_schedule(unsigned char input[W_END], const unsigned char m_hat[32],
                       const unsigned char pk_seed[XMSS_PK_SEED_BYTES])
{
    unsigned char com[HM_COM_BYTES], d[32], mh[32], coords[XMSS_WOTS_LEN];
    hm_commit(m_hat, input + W_R_OFF, input + W_A_OFF, com, d);
    uint32_t epoch = 0;
    for (int b = 0; b < XMSS_EPOCH_BYTES; b++)
        epoch = (epoch << 8) | input[W_LEAFIDX_OFF + b];
    xmss_hash_message(pk_seed, epoch, input + W_NONCE_OFF, XMSS_NONCE_LEN,
                       d, sizeof d, mh);
    if (!xmss_extract_coords(mh, coords)) return 0;
    int slot = 0;
    for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
        for (int pos = coords[ci]; pos < XMSS_WOTS_MAX_STEPS; pos++) {
            if (slot == W_SCHEDULE_LEN) return 0;
            input[W_SCHEDULE_OFF + slot++] = (unsigned char)ci;
        }
    }
    return slot == W_SCHEDULE_LEN;
}

static uint32_t shr32(uint32_t v, int k) { return k >= 32 ? 0u : v >> k; }

static void put_idx_le(unsigned char *p, uint32_t idx)
{
    for (int k = 0; k < 4; k++) p[k] = (unsigned char)((idx >> (8 * k)) & 0xFF);
}

static void mask_from_bit(const mw *sel, mw *mask)
{
    mask->h = 0u - (sel->h & 1u);
    for (int i = 0; i < N_PARTIES; i++) mask->l[i] = 0u - (sel->l[i] & 1u);
}

static void mh_coord_bits(const unsigned char mh_pub[32],
                          unsigned char mh_lam[N_PARTIES][32], int ci,
                          mw bits[XMSS_COORD_RES_BITS])
{
    const size_t pos = xmss_coord_bit_pos(ci);
    for (int k = 0; k < XMSS_COORD_RES_BITS; k++) {
        const size_t j = pos + (size_t)k;
        bits[k].h = mh_bit(mh_pub, j);
        for (int i = 0; i < N_PARTIES; i++) bits[k].l[i] = mh_bit(mh_lam[i], j);
    }
}

static void mh_coord(const unsigned char mh_pub[32],
                     unsigned char mh_lam[N_PARTIES][32], int ci, mw *out)
{
    mw bits[XMSS_COORD_RES_BITS];
    mh_coord_bits(mh_pub, mh_lam, ci, bits);
    mw_const(0, out);
    for (int k = 0; k < XMSS_COORD_RES_BITS; k++) {
        out->h |= (bits[k].h & 1u) << k;
        for (int i = 0; i < N_PARTIES; i++) out->l[i] |= (bits[k].l[i] & 1u) << k;
    }
}

static void mpc_gf128_mul(
    const mw X[4], const mw Y[4], mw out[4],
    unsigned char *tapes[N_PARTIES], uint32_t *aux, uint32_t *s_all, int *gc)
{
    uint32_t acc_pub[8];
    uint32_t acc_lam[N_PARTIES][8];
    memset(acc_pub, 0, sizeof(acc_pub));
    memset(acc_lam, 0, sizeof(acc_lam));
    for (int j = 0; j < 128; j++) {
        mw mask;
        mask.h = 0u - ((Y[j >> 5].h >> (j & 31)) & 1u);
        for (int i = 0; i < N_PARTIES; i++)
            mask.l[i] = 0u - ((Y[j >> 5].l[i] >> (j & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            mw mwout;
            mpc_AND(&mask, &X[w], &mwout, tapes, aux, s_all, gc);
            gf128_word_shift_xor(acc_pub, mwout.h, 32 * w + j);
            for (int i = 0; i < N_PARTIES; i++)
                gf128_word_shift_xor(acc_lam[i], mwout.l[i], 32 * w + j);
        }
    }
    uint32_t red[4];
    gf128_reduce(acc_pub, red);
    for (int w = 0; w < 4; w++) out[w].h = red[w];
    for (int i = 0; i < N_PARTIES; i++) {
        gf128_reduce(acc_lam[i], red);
        for (int w = 0; w < 4; w++) out[w].l[i] = red[w];
    }
}

void building_views(
    a *a, const unsigned char message_digest[32],
    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    const unsigned char *d_pub,
    unsigned char *lam[N_PARTIES],
    unsigned char *tapes[N_PARTIES],
    uint32_t *aux, uint32_t *s_all,
    const unsigned char *r_j, uint32_t zh_out[8])
{
    int gc = 0;

    unsigned char dsh_pub[32], dsh_lam_buf[N_PARTIES][32];
    unsigned char *dsh_lam[N_PARTIES];
    for (int i = 0; i < N_PARTIES; i++) dsh_lam[i] = dsh_lam_buf[i];
    {

        unsigned char ysh_pub[32], ysh_lam_buf[N_PARTIES][32];
        unsigned char *ysh_lam[N_PARTIES], *sec_lam[N_PARTIES];
        for (int i = 0; i < N_PARTIES; i++) {
            ysh_lam[i] = ysh_lam_buf[i];
            sec_lam[i] = lam[i] + W_R_OFF;
        }
        mpc_blake3_th(HM_DOM_Y, NULL, 3,
                      d_pub + W_R_OFF, sec_lam, HM_R_BYTES,
                      ysh_pub, ysh_lam, 32, tapes, aux, s_all, &gc);

        unsigned char bsh_pub[HM_B_BYTES], bsh_lam[N_PARTIES][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            mw acc[4];
            for (int w = 0; w < 4; w++) mw_const(0, &acc[w]);
            for (int idx = 0; idx < HM_NONCES; idx++) {
                mw A[4], R[4], P[4];
                uint32_t tmp4[4];
                gf128_load(tmp4, d_pub + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                for (int w = 0; w < 4; w++) A[w].h = tmp4[w];
                gf128_load(tmp4, d_pub + W_R_OFF + idx * HM_ELT);
                for (int w = 0; w < 4; w++) R[w].h = tmp4[w];
                for (int i = 0; i < N_PARTIES; i++) {
                    gf128_load(tmp4, lam[i] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    for (int w = 0; w < 4; w++) A[w].l[i] = tmp4[w];
                    gf128_load(tmp4, lam[i] + W_R_OFF + idx * HM_ELT);
                    for (int w = 0; w < 4; w++) R[w].l[i] = tmp4[w];
                }
                mpc_gf128_mul(A, R, P, tapes, aux, s_all, &gc);
                for (int w = 0; w < 4; w++) mpc_XOR(&acc[w], &P[w], &acc[w]);
            }

            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++) acc[w].h ^= Mk[w];
            uint32_t tmp4[4];
            for (int w = 0; w < 4; w++) tmp4[w] = acc[w].h;
            gf128_store(bsh_pub + line * HM_ELT, tmp4);
            for (int i = 0; i < N_PARTIES; i++) {
                for (int w = 0; w < 4; w++) tmp4[w] = acc[w].l[i];
                gf128_store(bsh_lam[i] + line * HM_ELT, tmp4);
            }
        }

        unsigned char sec_pub[HM_COM_BYTES], secbuf[N_PARTIES][HM_COM_BYTES];
        unsigned char *sec_lam2[N_PARTIES];
        memcpy(sec_pub, d_pub + W_A_OFF, HM_A_BYTES);
        memcpy(sec_pub + HM_A_BYTES, bsh_pub, HM_B_BYTES);
        memcpy(sec_pub + HM_A_BYTES + HM_B_BYTES, ysh_pub, HM_Y_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], lam[i] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES, bsh_lam[i], HM_B_BYTES);
            memcpy(secbuf[i] + HM_A_BYTES + HM_B_BYTES, ysh_lam_buf[i], HM_Y_BYTES);
            sec_lam2[i] = secbuf[i];
        }
        mpc_blake3_th(HM_DOM_D, NULL, 3, sec_pub, sec_lam2, HM_COM_BYTES,
                      dsh_pub, dsh_lam, 32, tapes, aux, s_all, &gc);
    }

    unsigned char mh_pub[32], mh_lam[N_PARTIES][32];
    {

        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memset(dombuf[i], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[i] + XMSS_PK_SEED_BYTES + 1, lam[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[i] = dombuf[i];
        }
        const int slen = XMSS_NONCE_LEN + 32;
        unsigned char sec_pub[XMSS_NONCE_LEN + 32];
        unsigned char secbuf[N_PARTIES][XMSS_NONCE_LEN + 32];
        unsigned char *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
        memcpy(sec_pub, d_pub + W_NONCE_OFF, XMSS_NONCE_LEN);
        memcpy(sec_pub + XMSS_NONCE_LEN, dsh_pub, 32);
        for (int i = 0; i < N_PARTIES; i++) {
            memcpy(secbuf[i], lam[i] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[i] + XMSS_NONCE_LEN, dsh_lam_buf[i], 32);
            sec_lam[i] = secbuf[i]; out_lam[i] = mh_lam[i];
        }
        mpc_blake3_th(dom_pub, dom_lam, dlen, sec_pub, sec_lam, slen,
                      mh_pub, out_lam, 32, tapes, aux, s_all, &gc);
    }

    unsigned char pkh_pub[XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    unsigned char pkh_lam[N_PARTIES][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    mw pool_check;
    pool_context pool_ctx = { .tapes = tapes, .transcript = s_all, .gc = &gc,
        .aux = aux };
    pool_chains(d_pub, lam, pk_seed, mh_pub, mh_lam, pkh_pub, pkh_lam,
                 &pool_check, &pool_ctx);

    unsigned char node_pub[XMSS_NODE_BYTES], node_lam[N_PARTIES][XMSS_NODE_BYTES];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES], *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_LEAF;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int i = 0; i < N_PARTIES; i++) {
            memset(dombuf[i], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[i] + XMSS_PK_SEED_BYTES + 1, lam[i] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[i] = dombuf[i]; sec_lam[i] = pkh_lam[i]; out_lam[i] = node_lam[i];
        }
        mpc_blake3_th(dom_pub, dom_lam, dlen,
                      pkh_pub, sec_lam, XMSS_WOTS_LEN * XMSS_NODE_BYTES,
                      node_pub, out_lam, XMSS_NODE_BYTES, tapes, aux, s_all, &gc);
    }

    {
        mw li;
        {
            const unsigned char *b = d_pub + W_LEAFIDX_OFF;
            li.h = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                 | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
            for (int i = 0; i < N_PARTIES; i++) {
                const unsigned char *bl = lam[i] + W_LEAFIDX_OFF;
                li.l[i] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16)
                        | ((uint32_t)bl[2] <<  8) | (uint32_t)bl[3];
            }
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib_pub[XMSS_NODE_BYTES], sib_lam[N_PARTIES][XMSS_NODE_BYTES];
            memcpy(sib_pub, d_pub + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int i = 0; i < N_PARTIES; i++)
                memcpy(sib_lam[i], lam[i] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            mw bitw, mask;
            bitw.h = (li.h >> level) & 1u;
            for (int i = 0; i < N_PARTIES; i++) bitw.l[i] = (li.l[i] >> level) & 1u;
            mask_from_bit(&bitw, &mask);

            unsigned char left_pub[XMSS_NODE_BYTES], right_pub[XMSS_NODE_BYTES];
            unsigned char left_lam[N_PARTIES][XMSS_NODE_BYTES];
            unsigned char right_lam[N_PARTIES][XMSS_NODE_BYTES];
            for (int w = 0; w < XMSS_NODE_WORDS; w++) {
                mw nd, sb, t, mt, lw, rw;
                nd.h = xmss_node_load_word(node_pub, (size_t)w);
                sb.h = xmss_node_load_word(sib_pub, (size_t)w);
                for (int i = 0; i < N_PARTIES; i++) {
                    nd.l[i] = xmss_node_load_word(node_lam[i], (size_t)w);
                    sb.l[i] = xmss_node_load_word(sib_lam[i], (size_t)w);
                }
                mpc_XOR(&nd, &sb, &t);
                mpc_AND(&mask, &t, &mt, tapes, aux, s_all, &gc);
                mpc_XOR(&nd, &mt, &lw);
                mpc_XOR(&sb, &mt, &rw);
                xmss_node_store_word(left_pub, (size_t)w, lw.h);
                xmss_node_store_word(right_pub, (size_t)w, rw.h);
                for (int i = 0; i < N_PARTIES; i++) {
                    xmss_node_store_word(left_lam[i], (size_t)w, lw.l[i]);
                    xmss_node_store_word(right_lam[i], (size_t)w, rw.l[i]);
                }
            }

            const int dlen = XMSS_PK_SEED_BYTES + 2 + 4;
            unsigned char dom_pub[XMSS_PK_SEED_BYTES + 2 + 4];
            unsigned char dombuf[N_PARTIES][XMSS_PK_SEED_BYTES + 2 + 4];
            unsigned char sec_pub[2 * XMSS_NODE_BYTES];
            unsigned char secbuf[N_PARTIES][2 * XMSS_NODE_BYTES];
            unsigned char *dom_lam[N_PARTIES], *sec_lam[N_PARTIES], *out_lam[N_PARTIES];
            memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
            dom_pub[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            dom_pub[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            put_idx_le(dom_pub + dlen - 4, shr32(li.h, level + 1));
            memcpy(sec_pub, left_pub, XMSS_NODE_BYTES);
            memcpy(sec_pub + XMSS_NODE_BYTES, right_pub, XMSS_NODE_BYTES);
            for (int i = 0; i < N_PARTIES; i++) {
                memset(dombuf[i], 0, dlen - 4);
                put_idx_le(dombuf[i] + dlen - 4, shr32(li.l[i], level + 1));
                memcpy(secbuf[i], left_lam[i], XMSS_NODE_BYTES);
                memcpy(secbuf[i] + XMSS_NODE_BYTES, right_lam[i], XMSS_NODE_BYTES);
                dom_lam[i] = dombuf[i]; sec_lam[i] = secbuf[i]; out_lam[i] = node_lam[i];
            }
            mpc_blake3_th(dom_pub, dom_lam, dlen, sec_pub, sec_lam,
                          2 * XMSS_NODE_BYTES, node_pub, out_lam,
                          XMSS_NODE_BYTES, tapes, aux, s_all, &gc);
        }
    }

    mw acc, leftover;
    mw_const(0, &acc);
    {
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            mw coord;
            mh_coord(mh_pub, mh_lam, ci, &coord);
            mpc_ADD(&acc, &coord, &acc, tapes, aux, s_all, &gc);
        }

        mw_const(0, &leftover);
        leftover.h = mh_bit(mh_pub, 63) | (mh_bit(mh_pub, 8 * XMSS_MSG_HASH_LEN - 1) << 1);
        for (int i = 0; i < N_PARTIES; i++)
            leftover.l[i] = mh_bit(mh_lam[i], 63)
                          | (mh_bit(mh_lam[i], 8 * XMSS_MSG_HASH_LEN - 1) << 1);
    }

    for (int w = 0; w < YP_ROOT_WORDS; w++) {
        zh_out[w] = xmss_node_load_word(node_pub, (size_t)w);
        for (int i = 0; i < N_PARTIES; i++)
            a->yp[i][w] = xmss_node_load_word(node_lam[i], (size_t)w);
    }
    zh_out[YP_SUM_WORD] = acc.h;
    zh_out[YP_LEFTOVER_WORD] = leftover.h;
    zh_out[YP_POOL_WORD] = pool_check.h;
    for (int i = 0; i < N_PARTIES; i++) {
        a->yp[i][YP_SUM_WORD] = acc.l[i];
        a->yp[i][YP_LEFTOVER_WORD] = leftover.l[i];
        a->yp[i][YP_POOL_WORD] = pool_check.l[i];
    }
    for (int w = YP_POOL_WORD + 1; w < 8; w++) {
        zh_out[w] = 0;
        for (int i = 0; i < N_PARTIES; i++) a->yp[i][w] = 0;
    }

    if (!omp_in_parallel()) g_circuit_gates = gc;

    if (s_all) compute_h_prime(d_pub, s_all, r_j, a->h_prime);
}

static void mask_from_bit_v(const mwv *sel, mwv *mask)
{
    mask->h = 0u - (sel->h & 1u);
    for (int j = 0; j < N_PARTIES-1; j++) mask->l[j] = 0u - (sel->l[j] & 1u);
}

static void mh_coord_bits_v(const unsigned char mh_pub[32],
                            unsigned char mh_lam[N_PARTIES-1][32], int ci,
                            mwv bits[XMSS_COORD_RES_BITS])
{
    const size_t pos = xmss_coord_bit_pos(ci);
    for (int k = 0; k < XMSS_COORD_RES_BITS; k++) {
        const size_t j = pos + (size_t)k;
        bits[k].h = mh_bit(mh_pub, j);
        for (int p = 0; p < N_PARTIES-1; p++) bits[k].l[p] = mh_bit(mh_lam[p], j);
    }
}

static void mh_coord_v(const unsigned char mh_pub[32],
                       unsigned char mh_lam[N_PARTIES-1][32], int ci, mwv *out)
{
    mwv bits[XMSS_COORD_RES_BITS];
    mh_coord_bits_v(mh_pub, mh_lam, ci, bits);
    mwv_const(0, out);
    for (int k = 0; k < XMSS_COORD_RES_BITS; k++) {
        out->h |= (bits[k].h & 1u) << k;
        for (int p = 0; p < N_PARTIES-1; p++) out->l[p] |= (bits[k].l[p] & 1u) << k;
    }
}

static void mpc_gf128_mul_verify(
    const mwv X[4], const mwv Y[4], mwv out[4],
    unsigned char *tapes[N_PARTIES-1], int e,
    const uint32_t *msgs_e, const uint32_t *aux,
    uint32_t *s_slots, int *gc)
{
    uint32_t acc_pub[8];
    uint32_t acc_lam[N_PARTIES-1][8];
    memset(acc_pub, 0, sizeof(acc_pub));
    memset(acc_lam, 0, sizeof(acc_lam));
    for (int bit = 0; bit < 128; bit++) {
        mwv mask;
        mask.h = 0u - ((Y[bit >> 5].h >> (bit & 31)) & 1u);
        for (int j = 0; j < N_PARTIES-1; j++)
            mask.l[j] = 0u - ((Y[bit >> 5].l[j] >> (bit & 31)) & 1u);
        for (int w = 0; w < 4; w++) {
            mwv mwout;
            mpc_AND_verify(&mask, &X[w], &mwout, tapes, e, msgs_e, aux, s_slots, gc);
            gf128_word_shift_xor(acc_pub, mwout.h, 32 * w + bit);
            for (int j = 0; j < N_PARTIES-1; j++)
                gf128_word_shift_xor(acc_lam[j], mwout.l[j], 32 * w + bit);
        }
    }
    uint32_t red[4];
    gf128_reduce(acc_pub, red);
    for (int w = 0; w < 4; w++) out[w].h = red[w];
    for (int j = 0; j < N_PARTIES-1; j++) {
        gf128_reduce(acc_lam[j], red);
        for (int w = 0; w < 4; w++) out[w].l[j] = red[w];
    }
}

void verify(
    const unsigned char message_digest[32],
    const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
    bool *error, a *a_struct, int e, z *z_proof, uint32_t zh_out[8])
{

    unsigned char *tapes[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) tapes[j] = NULL;
    for (int j = 0; j < N_PARTIES-1; j++) {
        tapes[j] = malloc((size_t)TAPE_SIZE);
        if (!tapes[j]) {
            for (int k = 0; k < j; k++) free(tapes[k]);
            *error = true; return;
        }
        expand_tape(z_proof->ke[j], tapes[j]);
    }

    uint32_t *s_slots = malloc((size_t)(N_PARTIES-1) * ySize * sizeof(uint32_t));
    unsigned char *xbuf = malloc((size_t)(N_PARTIES-1) * INPUT_LEN);
    if (!s_slots || !xbuf) {
        free(s_slots); free(xbuf);
        for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
        *error = true; return;
    }
    unsigned char *vlam[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) {
        vlam[j] = xbuf + (size_t)j * INPUT_LEN;
        expand_xshare(z_proof->ke[j], vlam[j]);
    }
    const unsigned char *d_pub = z_proof->x_offset;

    int gc = 0;
    const uint32_t *msgs_e = z_proof->msgs_e;

    unsigned char dsh_pub[32], dsh_lam_buf[N_PARTIES-1][32];
    unsigned char *dsh_lam[N_PARTIES-1];
    for (int j = 0; j < N_PARTIES-1; j++) dsh_lam[j] = dsh_lam_buf[j];
    {
        unsigned char ysh_pub[32], ysh_lam_buf[N_PARTIES-1][32];
        unsigned char *ysh_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            ysh_lam[j] = ysh_lam_buf[j];
            sec_lam[j] = vlam[j] + W_R_OFF;
        }
        mpc_blake3_th_verify(HM_DOM_Y, NULL, 3,
                             d_pub + W_R_OFF, sec_lam, HM_R_BYTES,
                             ysh_pub, ysh_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);

        unsigned char bsh_pub[HM_B_BYTES], bsh_lam[N_PARTIES-1][HM_B_BYTES];
        for (int line = 0; line < HM_LINES; line++) {
            mwv acc[4];
            for (int w = 0; w < 4; w++) mwv_const(0, &acc[w]);
            for (int idx = 0; idx < HM_NONCES; idx++) {
                mwv A[4], R[4], P[4];
                uint32_t tmp4[4];
                gf128_load(tmp4, d_pub + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                for (int w = 0; w < 4; w++) A[w].h = tmp4[w];
                gf128_load(tmp4, d_pub + W_R_OFF + idx * HM_ELT);
                for (int w = 0; w < 4; w++) R[w].h = tmp4[w];
                for (int j = 0; j < N_PARTIES-1; j++) {
                    gf128_load(tmp4, vlam[j] + W_A_OFF + (line * HM_NONCES + idx) * HM_ELT);
                    for (int w = 0; w < 4; w++) A[w].l[j] = tmp4[w];
                    gf128_load(tmp4, vlam[j] + W_R_OFF + idx * HM_ELT);
                    for (int w = 0; w < 4; w++) R[w].l[j] = tmp4[w];
                }
                mpc_gf128_mul_verify(A, R, P, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
                for (int w = 0; w < 4; w++) mpc_XOR_v(&acc[w], &P[w], &acc[w]);
            }
            uint32_t Mk[4];
            gf128_load(Mk, message_digest + line * HM_ELT);
            for (int w = 0; w < 4; w++) acc[w].h ^= Mk[w];
            uint32_t tmp4[4];
            for (int w = 0; w < 4; w++) tmp4[w] = acc[w].h;
            gf128_store(bsh_pub + line * HM_ELT, tmp4);
            for (int j = 0; j < N_PARTIES-1; j++) {
                for (int w = 0; w < 4; w++) tmp4[w] = acc[w].l[j];
                gf128_store(bsh_lam[j] + line * HM_ELT, tmp4);
            }
        }

        unsigned char sec_pub[HM_COM_BYTES], secbuf[N_PARTIES-1][HM_COM_BYTES];
        unsigned char *sec_lam2[N_PARTIES-1];
        memcpy(sec_pub, d_pub + W_A_OFF, HM_A_BYTES);
        memcpy(sec_pub + HM_A_BYTES, bsh_pub, HM_B_BYTES);
        memcpy(sec_pub + HM_A_BYTES + HM_B_BYTES, ysh_pub, HM_Y_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vlam[j] + W_A_OFF, HM_A_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES, bsh_lam[j], HM_B_BYTES);
            memcpy(secbuf[j] + HM_A_BYTES + HM_B_BYTES, ysh_lam_buf[j], HM_Y_BYTES);
            sec_lam2[j] = secbuf[j];
        }
        mpc_blake3_th_verify(HM_DOM_D, NULL, 3, sec_pub, sec_lam2, HM_COM_BYTES,
                             dsh_pub, dsh_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    unsigned char mh_pub[32], mh_lam[N_PARTIES-1][32];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES-1];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memset(dombuf[j], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[j] + XMSS_PK_SEED_BYTES + 1, vlam[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[j] = dombuf[j];
        }
        const int slen = XMSS_NONCE_LEN + 32;
        unsigned char sec_pub[XMSS_NONCE_LEN + 32];
        unsigned char secbuf[N_PARTIES-1][XMSS_NONCE_LEN + 32];
        unsigned char *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
        memcpy(sec_pub, d_pub + W_NONCE_OFF, XMSS_NONCE_LEN);
        memcpy(sec_pub + XMSS_NONCE_LEN, dsh_pub, 32);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memcpy(secbuf[j], vlam[j] + W_NONCE_OFF, XMSS_NONCE_LEN);
            memcpy(secbuf[j] + XMSS_NONCE_LEN, dsh_lam_buf[j], 32);
            sec_lam[j] = secbuf[j]; out_lam[j] = mh_lam[j];
        }
        mpc_blake3_th_verify(dom_pub, dom_lam, dlen, sec_pub, sec_lam, slen,
                             mh_pub, out_lam, 32,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    unsigned char pkh_pub[XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    unsigned char pkh_lam[N_PARTIES-1][XMSS_WOTS_LEN * XMSS_NODE_BYTES];
    mwv pool_check;
    pool_v_context pool_ctx = { .tapes = tapes, .transcript = s_slots, .gc = &gc,
        .aux = z_proof->aux, .msgs_e = msgs_e, .e = e };
    pool_v_chains(d_pub, vlam, pk_seed, mh_pub, mh_lam, pkh_pub, pkh_lam,
                   &pool_check, &pool_ctx);

    unsigned char node_pub[XMSS_NODE_BYTES];
    unsigned char node_lam[N_PARTIES-1][XMSS_NODE_BYTES];
    {
        const int dlen = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;
        unsigned char dom_pub[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
        unsigned char *dom_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
        memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
        dom_pub[XMSS_PK_SEED_BYTES] = XMSS_TWEAK_LEAF;
        memcpy(dom_pub + XMSS_PK_SEED_BYTES + 1, d_pub + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
        for (int j = 0; j < N_PARTIES-1; j++) {
            memset(dombuf[j], 0, XMSS_PK_SEED_BYTES + 1);
            memcpy(dombuf[j] + XMSS_PK_SEED_BYTES + 1, vlam[j] + W_LEAFIDX_OFF, XMSS_EPOCH_BYTES);
            dom_lam[j] = dombuf[j]; sec_lam[j] = pkh_lam[j]; out_lam[j] = node_lam[j];
        }
        mpc_blake3_th_verify(dom_pub, dom_lam, dlen,
                             pkh_pub, sec_lam, XMSS_WOTS_LEN * XMSS_NODE_BYTES,
                             node_pub, out_lam, XMSS_NODE_BYTES,
                             tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
    }

    {
        mwv li;
        {
            const unsigned char *b = d_pub + W_LEAFIDX_OFF;
            li.h = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                 | ((uint32_t)b[2] <<  8) | (uint32_t)b[3];
            for (int j = 0; j < N_PARTIES-1; j++) {
                const unsigned char *bl = vlam[j] + W_LEAFIDX_OFF;
                li.l[j] = ((uint32_t)bl[0] << 24) | ((uint32_t)bl[1] << 16)
                        | ((uint32_t)bl[2] <<  8) | (uint32_t)bl[3];
            }
        }
        for (int level = 0; level < XMSS_H; level++) {
            unsigned char sib_pub[XMSS_NODE_BYTES];
            unsigned char sib_lam[N_PARTIES-1][XMSS_NODE_BYTES];
            memcpy(sib_pub, d_pub + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);
            for (int j = 0; j < N_PARTIES-1; j++)
                memcpy(sib_lam[j], vlam[j] + W_PATH_OFF + level * XMSS_NODE_BYTES, XMSS_NODE_BYTES);

            mwv bitw, mask;
            bitw.h = (li.h >> level) & 1u;
            for (int j = 0; j < N_PARTIES-1; j++) bitw.l[j] = (li.l[j] >> level) & 1u;
            mask_from_bit_v(&bitw, &mask);

            unsigned char left_pub[XMSS_NODE_BYTES], right_pub[XMSS_NODE_BYTES];
            unsigned char left_lam[N_PARTIES-1][XMSS_NODE_BYTES];
            unsigned char right_lam[N_PARTIES-1][XMSS_NODE_BYTES];
            for (int w = 0; w < XMSS_NODE_WORDS; w++) {
                mwv nd, sb, t, mt, lw, rw;
                nd.h = xmss_node_load_word(node_pub, (size_t)w);
                sb.h = xmss_node_load_word(sib_pub, (size_t)w);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    nd.l[j] = xmss_node_load_word(node_lam[j], (size_t)w);
                    sb.l[j] = xmss_node_load_word(sib_lam[j], (size_t)w);
                }
                mpc_XOR_v(&nd, &sb, &t);
                mpc_AND_verify(&mask, &t, &mt, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
                mpc_XOR_v(&nd, &mt, &lw);
                mpc_XOR_v(&sb, &mt, &rw);
                xmss_node_store_word(left_pub, (size_t)w, lw.h);
                xmss_node_store_word(right_pub, (size_t)w, rw.h);
                for (int j = 0; j < N_PARTIES-1; j++) {
                    xmss_node_store_word(left_lam[j], (size_t)w, lw.l[j]);
                    xmss_node_store_word(right_lam[j], (size_t)w, rw.l[j]);
                }
            }

            const int dlen = XMSS_PK_SEED_BYTES + 2 + 4;
            unsigned char dom_pub[XMSS_PK_SEED_BYTES + 2 + 4];
            unsigned char dombuf[N_PARTIES-1][XMSS_PK_SEED_BYTES + 2 + 4];
            unsigned char sec_pub[2 * XMSS_NODE_BYTES];
            unsigned char secbuf[N_PARTIES-1][2 * XMSS_NODE_BYTES];
            unsigned char *dom_lam[N_PARTIES-1], *sec_lam[N_PARTIES-1], *out_lam[N_PARTIES-1];
            memcpy(dom_pub, pk_seed, XMSS_PK_SEED_BYTES);
            dom_pub[XMSS_PK_SEED_BYTES]     = XMSS_TWEAK_TREE;
            dom_pub[XMSS_PK_SEED_BYTES + 1] = (unsigned char)level;
            put_idx_le(dom_pub + dlen - 4, shr32(li.h, level + 1));
            memcpy(sec_pub, left_pub, XMSS_NODE_BYTES);
            memcpy(sec_pub + XMSS_NODE_BYTES, right_pub, XMSS_NODE_BYTES);
            for (int j = 0; j < N_PARTIES-1; j++) {
                memset(dombuf[j], 0, dlen - 4);
                put_idx_le(dombuf[j] + dlen - 4, shr32(li.l[j], level + 1));
                memcpy(secbuf[j], left_lam[j], XMSS_NODE_BYTES);
                memcpy(secbuf[j] + XMSS_NODE_BYTES, right_lam[j], XMSS_NODE_BYTES);
                dom_lam[j] = dombuf[j]; sec_lam[j] = secbuf[j]; out_lam[j] = node_lam[j];
            }
            mpc_blake3_th_verify(dom_pub, dom_lam, dlen, sec_pub, sec_lam,
                                 2 * XMSS_NODE_BYTES, node_pub, out_lam,
                                 XMSS_NODE_BYTES,
                                 tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
        }
    }

    mwv sum, leftover;
    mwv_const(0, &sum);
    {
        for (int ci = 0; ci < XMSS_WOTS_LEN; ci++) {
            mwv coord;
            mh_coord_v(mh_pub, mh_lam, ci, &coord);
            mpc_ADD_verify(&sum, &coord, &sum, tapes, e, msgs_e, z_proof->aux, s_slots, &gc);
        }
        mwv_const(0, &leftover);
        leftover.h = mh_bit(mh_pub, 63) | (mh_bit(mh_pub, 8 * XMSS_MSG_HASH_LEN - 1) << 1);
        for (int j = 0; j < N_PARTIES-1; j++)
            leftover.l[j] = mh_bit(mh_lam[j], 63)
                          | (mh_bit(mh_lam[j], 8 * XMSS_MSG_HASH_LEN - 1) << 1);
    }

    for (int w = 0; w < YP_ROOT_WORDS; w++)
        zh_out[w] = xmss_node_load_word(node_pub, (size_t)w);
    zh_out[YP_SUM_WORD] = sum.h;
    zh_out[YP_LEFTOVER_WORD] = leftover.h;
    zh_out[YP_POOL_WORD] = pool_check.h;
    for (int w = YP_POOL_WORD + 1; w < 8; w++) zh_out[w] = 0;

    for (int j = 0; j < N_PARTIES-1; j++) {
        int o = (j < e) ? j : j + 1;
        uint32_t lam_v;
        for (int w = 0; w < YP_ROOT_WORDS; w++) {
            lam_v = xmss_node_load_word(node_lam[j], (size_t)w);
            if (lam_v != a_struct->yp[o][w]) { *error = true; }
        }
        if (sum.l[j] != a_struct->yp[o][YP_SUM_WORD]) { *error = true; }
        if (leftover.l[j] != a_struct->yp[o][YP_LEFTOVER_WORD]) { *error = true; }
        if (pool_check.l[j] != a_struct->yp[o][YP_POOL_WORD]) { *error = true; }
        for (int w = YP_POOL_WORD + 1; w < 8; w++)
            if (a_struct->yp[o][w] != 0) { *error = true; }
    }

    recompute_h_prime_verify(e, d_pub, s_slots, msgs_e, z_proof->r_j,
                             a_struct->h_prime);

    free(s_slots);
    free(xbuf);
    for (int j = 0; j < N_PARTIES-1; j++) free(tapes[j]);
}
