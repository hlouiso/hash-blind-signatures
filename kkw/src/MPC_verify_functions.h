#ifndef MPC_VERIFY_FUNCTIONS_H
#define MPC_VERIFY_FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* The verifier reconstructs every mask share except the hidden party's. */
typedef struct { uint32_t h; uint32_t l[N_PARTIES - 1]; } mwv;

static inline void mwv_const(uint32_t K, mwv *z)
{
    z->h = K;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = 0;
}

static inline void mpc_XOR_v(const mwv *x, const mwv *y, mwv *z)
{
    z->h = x->h ^ y->h;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j] ^ y->l[j];
}

static inline void mpc_NEGATE_v(const mwv *x, mwv *z)
{
    z->h = ~x->h;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j];
}

static inline void mpc_RIGHTROTATE_v(const mwv *x, int n, mwv *z)
{
    z->h = RIGHTROTATE(x->h, n);
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = RIGHTROTATE(x->l[j], n);
}

static inline void mpc_RIGHTSHIFT_v(const mwv *x, int n, mwv *z)
{
    z->h = x->h >> n;
    for (int j = 0; j < N_PARTIES - 1; j++) z->l[j] = x->l[j] >> n;
}

void mpc_AND_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount);

void mpc_ADD_verify(const mwv *x, const mwv *y, mwv *z,
                    unsigned char *tapes[N_PARTIES - 1], int e,
                    const uint32_t *msgs_e, const uint32_t *aux,
                    uint32_t *s_slots, int *gateCount);

void mpc_blake3_compress_verify(const mwv cv[8], const mwv m[16],
                                uint32_t block_len, uint32_t flags, mwv out[8],
                                unsigned char *tapes[N_PARTIES - 1], int e,
                                const uint32_t *msgs_e, const uint32_t *aux,
                                uint32_t *s_slots, int *gateCount);

void mpc_blake3_th_verify(const unsigned char *dom_pub,
                          unsigned char *dom_lam[N_PARTIES - 1], int dom_len,
                          const unsigned char *data_pub,
                          unsigned char *data_lam[N_PARTIES - 1], int data_len,
                          unsigned char *out_pub,
                          unsigned char *out_lam[N_PARTIES - 1], int out_len,
                          unsigned char *tapes[N_PARTIES - 1], int e,
                          const uint32_t *msgs_e, const uint32_t *aux,
                          uint32_t *s_slots, int *gateCount);

#endif
