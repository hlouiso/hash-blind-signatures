#ifndef BLIND_MSS_PROTOCOL_H
#define BLIND_MSS_PROTOCOL_H

/* The proof establishes an HM opening of m_hat and an XMSS signature on the
 * commitment digest. pk_seed and root are authenticated external inputs; the
 * commitment and leaf index do not appear in the blind signature. */

#include "commitment.h"
#include "shared.h"
#include "xmss.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define BLIND_SK_SEED_BYTES 32
#define BLIND_SIGNER_KEY_BYTES (BLIND_SK_SEED_BYTES + XMSS_PK_SEED_BYTES + 1 + 8)
#define BLIND_SIGNER_PUB_BYTES (XMSS_NODE_BYTES + XMSS_PK_SEED_BYTES)

typedef struct
{
    uint8_t sk_seed[BLIND_SK_SEED_BYTES];
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    int height;
    uint64_t next_leaf;
    xmss_keypair *tree;
} blind_signer_key;

void blind_signer_key_free(blind_signer_key *key);

typedef struct
{
    uint8_t *msg;
    size_t msg_len;
    uint8_t com[HM_COM_BYTES];
    uint8_t r[HM_R_BYTES];
} blind_user_state;

void blind_msg_digest(const uint8_t *msg, size_t msg_len, uint8_t m_hat[32]);

int blind_keygen(blind_signer_key *key, int height, xmss_node root_out);

int blind_user_commit(const uint8_t *msg, size_t msg_len, blind_user_state *out);

int blind_signer_sign(blind_signer_key *key, const uint8_t com[HM_COM_BYTES], xmss_sig *out);

int blind_user_prove(const blind_user_state *st, const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                     const xmss_node root, const xmss_sig *sig, FILE *out);

int blind_verify_sig(FILE *proof, const uint8_t *msg, size_t msg_len,
                     const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root);

void blind_write_signer_key(const blind_signer_key *key, uint8_t out[BLIND_SIGNER_KEY_BYTES]);
int blind_read_signer_key(const uint8_t *buf, size_t len, blind_signer_key *out);

void blind_write_signer_pub(const xmss_node root, const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                            uint8_t out[BLIND_SIGNER_PUB_BYTES]);
int blind_read_signer_pub(const uint8_t *buf, size_t len, xmss_node root_out,
                          uint8_t pk_seed_out[XMSS_PK_SEED_BYTES]);

size_t blind_user_state_bytes(const blind_user_state *st);
void blind_write_user_state(const blind_user_state *st, uint8_t *out);

int blind_read_user_state(const uint8_t *buf, size_t len, blind_user_state *out);
void blind_user_state_free(blind_user_state *st);

#endif
