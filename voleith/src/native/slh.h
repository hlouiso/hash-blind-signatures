#ifndef VOLEITH_NATIVE_SLH_H
#define VOLEITH_NATIVE_SLH_H

/* SLH-DSA-SHAKE (FIPS 205 Algorithms 1-24, Section 11.1) at security
 * category 1, generic over the parameters. A port of
 * binius64/src/slh/native.rs with the SHAKE instantiation:
 *   F, H, T_l = SHAKE256(PK.seed || ADRS || M, 8n), the full 32-byte ADRS;
 *   PRF       = SHAKE256(PK.seed || ADRS || SK.seed, 8n);
 *   H_msg     = SHAKE256(R || PK.seed || PK.root || M, 8m);
 *   PRF_msg   = SHAKE256(SK.prf || opt_rand || M, 8n).
 * Signing runs the tree computations on pthreads; the top XMSS tree is
 * cached in the key, as SP 800-230 Section 3 permits. */

#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SLH_N 16

typedef struct {
    const char *name;
    uint32_t h, d, hp, a, k, lg_w, m;
} slh_params;

/* SP 800-230 ipd (April 2026), Table 1. */
extern const slh_params SLH_SHAKE_128_24;
/* The toy sets of binius64/tests/slh_dsa.rs. */
extern const slh_params SLH_TOY_W4;
extern const slh_params SLH_TOY_W16;

uint32_t slh_w(const slh_params *p);
uint32_t slh_len1(const slh_params *p);
uint32_t slh_len2(const slh_params *p);
uint32_t slh_len(const slh_params *p);
uint32_t slh_csum_shift(const slh_params *p);
uint32_t slh_csum_bytes(const slh_params *p);
uint32_t slh_md_bytes(const slh_params *p);
uint32_t slh_tree_bytes(const slh_params *p);
uint32_t slh_leaf_bytes(const slh_params *p);
size_t slh_sig_bytes(const slh_params *p);
int slh_params_ok(const slh_params *p);

/* Hash calls one verification makes: tweakable hashes plus the one H_msg. */
typedef struct {
    uint64_t f, h, t;
} slh_stats;

/* SHAKE256 of the concatenation of n parts. */
void slh_shake256(const uint8_t *const *parts, const size_t *lens, size_t n,
                  uint8_t *out, size_t out_len);
/* The Keccak-f[1600] state after absorbing one full 136-byte block. */
void slh_shake256_block_state(const uint8_t block[136], uint64_t state[25]);
/* Threads the signer uses: SLH_THREADS, else the online CPUs. */
size_t slh_threads(void);

/* M' = 0x00 || 0x00 || msg (Algorithms 22 and 24, empty context). Returns
 * len + 2; out must hold that many bytes. */
size_t slh_pure_message(const uint8_t *msg, size_t len, uint8_t *out);
void slh_h_msg(const slh_params *p, const uint8_t r[SLH_N],
               const uint8_t pk_seed[SLH_N], const uint8_t pk_root[SLH_N],
               const uint8_t *msg, size_t len, uint8_t *out /* m bytes */);
/* The len base-w digits of Algorithms 7 and 8: message, then checksum. */
void slh_wots_digits(const slh_params *p, const uint8_t msg[SLH_N], uint32_t *digits);

typedef struct slh_key slh_key;

/* Algorithm 18; NULL on allocation failure. */
slh_key *slh_keygen_internal(const slh_params *p, const uint8_t sk_seed[SLH_N],
                             const uint8_t sk_prf[SLH_N],
                             const uint8_t pk_seed[SLH_N]);
void slh_key_free(slh_key *key);
void slh_key_pk_seed(const slh_key *key, uint8_t out[SLH_N]);
void slh_key_pk_root(const slh_key *key, uint8_t out[SLH_N]);

/* The stored levels of the top-layer tree: heights slh_key_top_first(key)..h',
 * from the bottom up, slh_key_top_bytes(key) bytes in all. */
uint32_t slh_key_top_first(const slh_key *key);
size_t slh_key_top_bytes(const slh_key *key);
void slh_key_export_top(const slh_key *key, uint8_t *out);
/* Rebuilds a key from its seeds and exported top levels, without key
 * generation; NULL unless the levels form the upper part of the top-layer
 * tree, rooted at pk_root. */
slh_key *slh_key_from_top(const slh_params *p, const uint8_t sk_seed[SLH_N],
                          const uint8_t sk_prf[SLH_N], const uint8_t pk_seed[SLH_N],
                          const uint8_t pk_root[SLH_N], uint32_t first,
                          const uint8_t *levels, size_t len);

/* Algorithm 19, writing the FIPS 205 encoding R || SIG_FORS || SIG_HT;
 * addrnd = NULL is the deterministic variant. */
void slh_sign_internal(const slh_key *key, const uint8_t *msg, size_t len,
                       const uint8_t *addrnd, uint8_t *sig);
/* Pure SLH-DSA with an empty context (Algorithm 22, lines 8-9). */
void slh_sign(const slh_key *key, const uint8_t *msg, size_t len,
              const uint8_t *addrnd, uint8_t *sig);

/* Algorithm 20; stats may be NULL. Returns 1 when the signature verifies. */
int slh_verify_internal(const slh_params *p, const uint8_t pk_seed[SLH_N],
                        const uint8_t pk_root[SLH_N], const uint8_t *msg,
                        size_t len, const uint8_t *sig, size_t sig_len,
                        slh_stats *stats);
/* Algorithm 24 with an empty context. */
int slh_verify(const slh_params *p, const uint8_t pk_seed[SLH_N],
               const uint8_t pk_root[SLH_N], const uint8_t *msg, size_t len,
               const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif
#endif
