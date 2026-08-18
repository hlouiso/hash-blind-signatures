#ifndef XMSS_NATIVE_H
#define XMSS_NATIVE_H

/* Stateful target-sum WOTS+/XMSS. The circuit always verifies 32 levels;
 * a real height h < 32 is extended with key-derived fixed upper siblings.
 * Reusing a leaf invalidates the one-time-signature security argument. */

#include <stddef.h>
#include <stdint.h>

#define XMSS_NODE_BYTES 16
#define XMSS_NODE_WORDS (XMSS_NODE_BYTES / 4)
#define XMSS_PK_SEED_BYTES 16
#define XMSS_H 32
#define XMSS_H_DEFAULT 10
#define XMSS_SUBTREE_H 16
#define XMSS_WOTS_W 8
#define XMSS_WOTS_LOGW 3
#define XMSS_WOTS_LEN 42
#define XMSS_WOTS_MAX_STEPS 7
#define XMSS_TARGET_SUM 195
#define XMSS_NONCE_LEN 24
#define XMSS_MSG_HASH_LEN 16
#define XMSS_COORD_RES_BITS 3
#define XMSS_EPOCH_BYTES 4

#define XMSS_DIGITS_PER_WORD (XMSS_WOTS_LEN / 2)

_Static_assert(2 * XMSS_DIGITS_PER_WORD == XMSS_WOTS_LEN,
               "the codeword must split evenly across the two digest words");
_Static_assert(XMSS_WOTS_LEN * XMSS_COORD_RES_BITS + 2 == XMSS_MSG_HASH_LEN * 8,
               "digits plus the two leftover top bits must exhaust the digest");
_Static_assert(XMSS_WOTS_W == (1 << XMSS_WOTS_LOGW), "chain length must be 2^LOGW");
_Static_assert(XMSS_TARGET_SUM <= XMSS_WOTS_LEN * XMSS_WOTS_MAX_STEPS,
               "target sum is unreachable");
_Static_assert(XMSS_SUBTREE_H <= XMSS_H, "a bottom subtree must fit the tree");
_Static_assert(XMSS_H_DEFAULT >= 1 && XMSS_H_DEFAULT <= XMSS_H,
               "the default real height must fit the circuit's");

#define XMSS_TWEAK_CHAIN 0x00
#define XMSS_TWEAK_TREE 0x01
#define XMSS_TWEAK_MESSAGE 0x02
#define XMSS_TWEAK_LEAF 0x03

/* Nodes are 128-bit truncations; integer tweaks use the explicit byte order
 * implemented by the hash builders rather than host representation. */
typedef uint8_t xmss_node[XMSS_NODE_BYTES];

_Static_assert(XMSS_NODE_BYTES % 4 == 0, "a node must be a whole number of KKW words");

static inline uint32_t xmss_node_load_word(const uint8_t node[XMSS_NODE_BYTES], size_t word)
{
    uint32_t out = 0;
    for (size_t i = 0; i < 4; i++) out |= (uint32_t)node[4 * word + i] << (8 * i);
    return out;
}

static inline void xmss_node_store_word(uint8_t node[XMSS_NODE_BYTES], size_t word, uint32_t value)
{
    for (size_t i = 0; i < 4; i++) node[4 * word + i] = (uint8_t)(value >> (8 * i));
}

static inline size_t xmss_coord_bit_pos(int i)
{
    return (i < XMSS_DIGITS_PER_WORD)
               ? (size_t)XMSS_COORD_RES_BITS * (size_t)i
               : 64u + (size_t)XMSS_COORD_RES_BITS * (size_t)(i - XMSS_DIGITS_PER_WORD);
}

typedef struct
{
    uint32_t leaf_index;
    uint8_t nonce[XMSS_NONCE_LEN];
    xmss_node sig_hashes[XMSS_WOTS_LEN];

    xmss_node auth_path[XMSS_H];
} xmss_sig;

#define XMSS_SIG_BYTES (4 + XMSS_NONCE_LEN + XMSS_WOTS_LEN * XMSS_NODE_BYTES + XMSS_H * XMSS_NODE_BYTES)

void xmss_hash_message(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *nonce,
                       size_t nonce_len, const uint8_t *message, size_t message_len, uint8_t out32[32]);

void xmss_hash_chain_step(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node in,
                          uint8_t chain_idx, uint8_t pos, xmss_node out);

void xmss_hash_chain_multi(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node start,
                           uint8_t chain_idx, uint8_t start_pos, uint8_t steps, xmss_node out);

void xmss_hash_tree_node(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node left, const xmss_node right,
                         uint32_t level, uint32_t index, xmss_node out);

void xmss_hash_public_key(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node pk_hashes[XMSS_WOTS_LEN], xmss_node out);

int xmss_extract_coords(const uint8_t hash[XMSS_MSG_HASH_LEN], uint8_t coords_out[XMSS_WOTS_LEN]);

void xmss_wots_gen_sk(const uint8_t sk_seed[32], uint32_t leaf_index, xmss_node sk_out[XMSS_WOTS_LEN]);

void xmss_wots_pk_from_sk(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node sk[XMSS_WOTS_LEN], xmss_node pk_out[XMSS_WOTS_LEN]);

void xmss_wots_sign(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node sk[XMSS_WOTS_LEN],
                    const uint8_t coords[XMSS_WOTS_LEN], xmss_node sig_out[XMSS_WOTS_LEN]);

void xmss_wots_pk_from_sig(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                           const xmss_node sig[XMSS_WOTS_LEN], const uint8_t coords[XMSS_WOTS_LEN],
                           xmss_node pk_out[XMSS_WOTS_LEN]);

typedef struct xmss_keypair xmss_keypair;

xmss_keypair *xmss_keypair_new(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                               int height);

xmss_keypair *xmss_keypair_new_split(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                                     int height, int subtree_h);
void xmss_keypair_free(xmss_keypair *kp);

void xmss_keypair_root(const xmss_keypair *kp, xmss_node root_out);

int xmss_keypair_height(const xmss_keypair *kp);
uint64_t xmss_keypair_capacity(const xmss_keypair *kp);

int xmss_keypair_sign(xmss_keypair *kp, uint32_t leaf_index, const uint8_t *message, size_t message_len,
                      xmss_sig *out);

void xmss_compute_root(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], int height,
                       xmss_node root_out);

int xmss_sign(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], int height,
              uint32_t leaf_index, const uint8_t *message, size_t message_len, xmss_sig *out);

int xmss_verify(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root, const uint8_t *message,
                size_t message_len, const xmss_sig *sig);

void xmss_write_sig(const xmss_sig *sig, uint8_t out[XMSS_SIG_BYTES]);

int xmss_read_sig(const uint8_t *buf, size_t len, xmss_sig *out);

#endif
