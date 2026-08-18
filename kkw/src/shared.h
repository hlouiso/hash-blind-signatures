#ifndef SHARED_H
#define SHARED_H

#include "blake3_th.h"
#include "xmss.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The tables target 128-GRIND_W cut-and-choose bits. Grinding restores total
 * classical work to 2^128 by requiring GRIND_W zero challenge bits. */
#ifndef N_PARTIES
#define N_PARTIES 4
#endif

#ifndef GRIND_W
#define GRIND_W 16
#endif

_Static_assert(GRIND_W >= 0 && GRIND_W < 30, "GRIND_W must fit the uint32 grinding counter");

#if GRIND_W == 0
#  if   N_PARTIES == 4
#    define M_KKW 218
#    define NUM_ROUNDS 65
#  elif N_PARTIES == 8
#    define M_KKW 252
#    define NUM_ROUNDS 44
#  elif N_PARTIES == 12
#    define M_KKW 295
#    define NUM_ROUNDS 37
#  elif N_PARTIES == 16
#    define M_KKW 352
#    define NUM_ROUNDS 33
#  elif N_PARTIES == 20
#    define M_KKW 366
#    define NUM_ROUNDS 31
#  elif N_PARTIES == 24
#    define M_KKW 425
#    define NUM_ROUNDS 29
#  elif N_PARTIES == 28
#    define M_KKW 433
#    define NUM_ROUNDS 28
#  elif N_PARTIES == 32
#    define M_KKW 462
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 64
#    define M_KKW 631
#    define NUM_ROUNDS 23
#  elif N_PARTIES == 128
#    define M_KKW 916
#    define NUM_ROUNDS 20
#  elif N_PARTIES == 256
#    define M_KKW 1794
#    define NUM_ROUNDS 17
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 16
#  if   N_PARTIES == 4
#    define M_KKW 189
#    define NUM_ROUNDS 57
#  elif N_PARTIES == 8
#    define M_KKW 209
#    define NUM_ROUNDS 39
#  elif N_PARTIES == 12
#    define M_KKW 237
#    define NUM_ROUNDS 33
#  elif N_PARTIES == 16
#    define M_KKW 301
#    define NUM_ROUNDS 29
#  elif N_PARTIES == 20
#    define M_KKW 330
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 24
#    define M_KKW 327
#    define NUM_ROUNDS 26
#  elif N_PARTIES == 28
#    define M_KKW 344
#    define NUM_ROUNDS 25
#  elif N_PARTIES == 32
#    define M_KKW 374
#    define NUM_ROUNDS 24
#  elif N_PARTIES == 64
#    define M_KKW 573
#    define NUM_ROUNDS 20
#  elif N_PARTIES == 128
#    define M_KKW 963
#    define NUM_ROUNDS 17
#  elif N_PARTIES == 256
#    define M_KKW 1488
#    define NUM_ROUNDS 15
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#elif GRIND_W == 24
#  if   N_PARTIES == 4
#    define M_KKW 175
#    define NUM_ROUNDS 53
#  elif N_PARTIES == 8
#    define M_KKW 199
#    define NUM_ROUNDS 36
#  elif N_PARTIES == 12
#    define M_KKW 211
#    define NUM_ROUNDS 31
#  elif N_PARTIES == 16
#    define M_KKW 276
#    define NUM_ROUNDS 27
#  elif N_PARTIES == 20
#    define M_KKW 259
#    define NUM_ROUNDS 26
#  elif N_PARTIES == 24
#    define M_KKW 314
#    define NUM_ROUNDS 24
#  elif N_PARTIES == 28
#    define M_KKW 335
#    define NUM_ROUNDS 23
#  elif N_PARTIES == 32
#    define M_KKW 372
#    define NUM_ROUNDS 22
#  elif N_PARTIES == 64
#    define M_KKW 474
#    define NUM_ROUNDS 19
#  elif N_PARTIES == 128
#    define M_KKW 823
#    define NUM_ROUNDS 16
#  elif N_PARTIES == 256
#    define M_KKW 1339
#    define NUM_ROUNDS 14
#  else
#    error "Unsupported N_PARTIES: no KKW (M,τ) parameters in table"
#  endif
#else
#  error "Unsupported GRIND_W: no (tau,M) parameter table"
#endif

_Static_assert(N_PARTIES >= 4 && N_PARTIES <= 256, "N_PARTIES must be 4..256");
_Static_assert(NUM_ROUNDS < M_KKW, "NUM_ROUNDS must be < M_KKW");

#define SEED_SIZE 32
extern const int ySize;
extern const int INPUT_LEN;

extern const int lib_n_parties, lib_m_kkw, lib_num_rounds;
#define ASSERT_LIB_PARAMS() do { \
    if (lib_n_parties != N_PARTIES || lib_m_kkw != M_KKW || \
        lib_num_rounds != NUM_ROUNDS) { \
        fprintf(stderr, "libblindmss parameter mismatch: binary N=%d M=%d " \
                "tau=%d vs library N=%d M=%d tau=%d (rebuild with the same " \
                "N/W flags)\n", N_PARTIES, M_KKW, NUM_ROUNDS, \
                lib_n_parties, lib_m_kkw, lib_num_rounds); \
        exit(1); \
    } } while (0)

extern const int TAPE_SIZE;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1u << (i)) : (x) & (~(1u << (i)))

typedef struct
{

    /* Output-mask shares: output = masked_output XOR XOR_i yp[i]. */
    uint32_t yp[N_PARTIES][8];

    /* h'_j = H(masked_witness || broadcasts || r_j). */
    unsigned char h_prime[32];
} a;

typedef struct
{
    /* Revealed seeds for every party except the hidden party e. */
    unsigned char ke[N_PARTIES - 1][SEED_SIZE];
    /* Masked witness and the hidden party's broadcast stream. */
    unsigned char *x_offset;
    uint32_t *aux;
    uint32_t *msgs_e;
    unsigned char com_hidden[32];

    /* Independent randomness: deriving it from the published seed_star would
     * make h'_j an offline witness-testing oracle and break zero knowledge. */
    unsigned char r_j[32];
} z;

void expand_tape(const unsigned char seed[SEED_SIZE], unsigned char *tape);

void expand_seed_star(const unsigned char seed_star[SEED_SIZE],
                      unsigned char seeds_out[N_PARTIES][SEED_SIZE]);

void expand_xshare(const unsigned char seed[SEED_SIZE], unsigned char *xshare_out);

void preproc_com_party(int party, const unsigned char seed[SEED_SIZE],
                        const uint32_t *aux,
                        unsigned char com_out[32]);

void preproc_commit_instance(unsigned char seeds[N_PARTIES][SEED_SIZE],
                              const uint32_t *aux,
                              unsigned char h_j_out[32]);

void compute_aux_from_seeds(unsigned char seeds[N_PARTIES][SEED_SIZE],
                             uint32_t *aux_out, unsigned char *h_out32);

void kkw_fs_prefix(const unsigned char msg[32], const uint32_t pubout[8],
                   const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
                   const unsigned char nonce[32],
                   const unsigned char h_star[32],
                   unsigned char h_pre[32]);

int kkw_fs_seed(const unsigned char h_pre[32], uint32_t ctr,
                unsigned char seed_FS[32]);

void kkw_fs_expand(const unsigned char seed_FS[32],
                   int C_out[NUM_ROUNDS], int p_out[NUM_ROUNDS]);

#define KKW_DOM_PPCOM  "KKWppcom"
#define KKW_DOM_HJ     "KKWhj"
#define KKW_DOM_HPRIME "KKWhprime"
#define KKW_DOM_HOUT   "KKWhout"
#define KKW_DOM_HSTAR1 "KKWhstar1"
#define KKW_DOM_HSTAR2 "KKWhstar2"
#define KKW_DOM_HSTAR3 "KKWhstar3"
#define KKW_DOM_HSTAR  "KKWhstar"
#define KKW_DOM_FS     "KKWfs"
#define KKW_DOM_GRIND  "KKWgrind"
#define KKW_DOM_PRG    "KKWprg"
#define KKW_DOM_MHAT   "KKWmhat"

/* These tags are pairwise distinct and disjoint from the XMSS/HM domains. */
#define KKW_TH(dom, data, len, out32) \
    blake3_th((const uint8_t *)"" dom, sizeof(dom) - 1, \
              (const uint8_t *)(data), (len), (out32), 32)
#define KKW_TH_INIT(ctx, dom) \
    blake3_th_init((ctx), (const uint8_t *)"" dom, sizeof(dom) - 1)

void compute_h_prime(const unsigned char *d_pub, const uint32_t *s_all,
                     const unsigned char r_j[32],
                     unsigned char h_prime[32]);

void compute_msgs_e(int e, const uint32_t *s_all, uint32_t *msgs_e_out);

void recompute_h_prime_verify(int e, const unsigned char *d_pub,
                               const uint32_t *s_slots,
                               const uint32_t *msgs_e,
                               const unsigned char r_j[32],
                               unsigned char h_prime_out[32]);

static inline uint32_t tape_get32(const unsigned char *tape, int pos)
{
    uint32_t v;
    memcpy(&v, tape + pos, 4);
    return v;
}

static inline uint32_t tape_lam(const unsigned char *tape, int g) { return tape_get32(tape, g * 4); }

static inline uint32_t tape_prod(const unsigned char *tape, int g) { return tape_get32(tape, ySize * 4 + g * 4); }

#endif
