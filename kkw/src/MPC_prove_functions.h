#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "shared.h"
#include <stdint.h>

/* h is the public masked value; l[i] is party i's share of its mask. */
typedef struct { uint32_t h; uint32_t l[N_PARTIES]; } mw;

static inline void mw_const(uint32_t K, mw *z)
{
    z->h = K;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = 0;
}

static inline void mpc_XOR(const mw *x, const mw *y, mw *z)
{
    z->h = x->h ^ y->h;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i] ^ y->l[i];
}

static inline void mpc_NEGATE(const mw *x, mw *z)
{
    z->h = ~x->h;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i];
}

static inline void mpc_RIGHTROTATE(const mw *x, int n, mw *z)
{
    z->h = RIGHTROTATE(x->h, n);
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = RIGHTROTATE(x->l[i], n);
}

static inline void mpc_RIGHTSHIFT(const mw *x, int n, mw *z)
{
    z->h = x->h >> n;
    for (int i = 0; i < N_PARTIES; i++) z->l[i] = x->l[i] >> n;
}

void mpc_AND(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount);

void mpc_ADD(const mw *x, const mw *y, mw *z,
             unsigned char *tapes[N_PARTIES], uint32_t *aux,
             uint32_t *s_all, int *gateCount);

void mpc_blake3_compress(const mw cv[8], const mw m[16], uint32_t block_len,
                         uint32_t flags, mw out[8],
                         unsigned char *tapes[N_PARTIES], uint32_t *aux,
                         uint32_t *s_all, int *gateCount);

void mpc_blake3_th(const unsigned char *dom_pub, unsigned char *dom_lam[N_PARTIES],
                   int dom_len,
                   const unsigned char *data_pub, unsigned char *data_lam[N_PARTIES],
                   int data_len,
                   unsigned char *out_pub, unsigned char *out_lam[N_PARTIES],
                   int out_len,
                   unsigned char *tapes[N_PARTIES], uint32_t *aux,
                   uint32_t *s_all, int *gateCount);

#endif
