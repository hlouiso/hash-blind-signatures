#include "protocol.h"

#include "circuits.h"
#include "kkw_prove.h"
#include "kkw_verify.h"
#include "randombytes.h"

#include <stdlib.h>
#include <string.h>

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_epoch_be(uint8_t *p, uint32_t v)
{
    for (int k = 0; k < XMSS_EPOCH_BYTES; k++)
        p[k] = (uint8_t)(v >> (8 * (XMSS_EPOCH_BYTES - 1 - k)));
}

static void build_pubout(const xmss_node root, uint32_t pubout[8])
{
    memset(pubout, 0, 8 * sizeof(uint32_t));
    for (int w = 0; w < YP_ROOT_WORDS; w++)
        pubout[w] = xmss_node_load_word(root, (size_t)w);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;
}

void blind_msg_digest(const uint8_t *msg, size_t msg_len, uint8_t m_hat[32])
{
    KKW_TH(KKW_DOM_MHAT, msg, msg_len, m_hat);
}

int blind_keygen(blind_signer_key *key, int height, xmss_node root_out)
{
    if (height < 1 || height > XMSS_H)
        return 0;
    key->tree = NULL;
    if (!randombytes_fill(key->sk_seed, sizeof key->sk_seed))
        return 0;
    if (!randombytes_fill(key->pk_seed, sizeof key->pk_seed))
        return 0;
    key->height = height;
    key->next_leaf = 0;

    key->tree = xmss_keypair_new(key->sk_seed, key->pk_seed, height);
    if (!key->tree)
        return 0;
    xmss_keypair_root(key->tree, root_out);
    return 1;
}

void blind_signer_key_free(blind_signer_key *key)
{
    xmss_keypair_free(key->tree);
    key->tree = NULL;
    volatile uint8_t *p = key->sk_seed;
    for (size_t i = 0; i < sizeof key->sk_seed; i++)
        p[i] = 0;
    memset(key->pk_seed, 0, sizeof key->pk_seed);
    key->next_leaf = 0;
}

int blind_user_commit(const uint8_t *msg, size_t msg_len, blind_user_state *out)
{
    uint8_t a[HM_A_BYTES], m_hat[32], d[32];

    out->msg = NULL;
    out->msg_len = 0;

    if (!randombytes_fill(out->r, sizeof out->r))
        return 0;
    if (!randombytes_fill(a, sizeof a))
        return 0;

    blind_msg_digest(msg, msg_len, m_hat);
    hm_commit(m_hat, out->r, a, out->com, d);

    out->msg_len = msg_len;
    if (msg_len > 0)
    {
        out->msg = malloc(msg_len);
        if (!out->msg)
            return 0;
        memcpy(out->msg, msg, msg_len);
    }
    return 1;
}

int blind_signer_sign(blind_signer_key *key, const uint8_t com[HM_COM_BYTES], xmss_sig *out)
{
    if (key->next_leaf >= (uint64_t)1u << key->height)
        return 0;

    uint8_t d[32];
    hm_digest(com, d);

    if (!key->tree)
    {
        key->tree = xmss_keypair_new(key->sk_seed, key->pk_seed, key->height);
        if (!key->tree)
            return 0;
    }

    if (!xmss_keypair_sign(key->tree, (uint32_t)key->next_leaf, d, sizeof d, out))
        return 0;
    key->next_leaf++;
    return 1;
}

int blind_user_prove(const blind_user_state *st, const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                     const xmss_node root, const xmss_sig *sig, FILE *out)
{
    unsigned char input[W_END];
    uint8_t m_hat[32];
    uint32_t pubout[8];

    blind_msg_digest(st->msg, st->msg_len, m_hat);

    memcpy(input + W_R_OFF, st->r, HM_R_BYTES);
    memcpy(input + W_A_OFF, st->com, HM_A_BYTES);
    put_epoch_be(input + W_LEAFIDX_OFF, sig->leaf_index);
    memcpy(input + W_NONCE_OFF, sig->nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig->sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig->auth_path[h], XMSS_NODE_BYTES);

    build_pubout(root, pubout);
    return kkw_prove(input, m_hat, pk_seed, pubout, out);
}

int blind_verify_sig(FILE *proof, const uint8_t *msg, size_t msg_len,
                     const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root)
{
    uint8_t m_hat[32];
    uint32_t pubout[8];
    blind_msg_digest(msg, msg_len, m_hat);
    build_pubout(root, pubout);
    return kkw_verify(proof, m_hat, pk_seed, pubout) == 0;
}

void blind_write_signer_key(const blind_signer_key *key, uint8_t out[BLIND_SIGNER_KEY_BYTES])
{
    memcpy(out, key->sk_seed, BLIND_SK_SEED_BYTES);
    memcpy(out + BLIND_SK_SEED_BYTES, key->pk_seed, XMSS_PK_SEED_BYTES);
    size_t o = BLIND_SK_SEED_BYTES + XMSS_PK_SEED_BYTES;
    out[o++] = (uint8_t)key->height;
    for (int k = 0; k < 8; k++)
        out[o++] = (uint8_t)((key->next_leaf >> (8 * k)) & 0xff);
}

int blind_read_signer_key(const uint8_t *buf, size_t len, blind_signer_key *out)
{
    out->tree = NULL;
    if (len != BLIND_SIGNER_KEY_BYTES)
        return 0;
    memcpy(out->sk_seed, buf, BLIND_SK_SEED_BYTES);
    memcpy(out->pk_seed, buf + BLIND_SK_SEED_BYTES, XMSS_PK_SEED_BYTES);
    size_t o = BLIND_SK_SEED_BYTES + XMSS_PK_SEED_BYTES;
    out->height = buf[o++];
    if (out->height < 1 || out->height > XMSS_H)
        return 0;
    out->next_leaf = 0;
    for (int k = 0; k < 8; k++)
        out->next_leaf |= (uint64_t)buf[o++] << (8 * k);
    return 1;
}

void blind_write_signer_pub(const xmss_node root, const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                            uint8_t out[BLIND_SIGNER_PUB_BYTES])
{
    memcpy(out, root, XMSS_NODE_BYTES);
    memcpy(out + XMSS_NODE_BYTES, pk_seed, XMSS_PK_SEED_BYTES);
}

int blind_read_signer_pub(const uint8_t *buf, size_t len, xmss_node root_out,
                          uint8_t pk_seed_out[XMSS_PK_SEED_BYTES])
{
    if (len != BLIND_SIGNER_PUB_BYTES)
        return 0;
    memcpy(root_out, buf, XMSS_NODE_BYTES);
    memcpy(pk_seed_out, buf + XMSS_NODE_BYTES, XMSS_PK_SEED_BYTES);
    return 1;
}

size_t blind_user_state_bytes(const blind_user_state *st)
{
    return 4 + st->msg_len + HM_COM_BYTES + HM_R_BYTES;
}

void blind_write_user_state(const blind_user_state *st, uint8_t *out)
{
    put_u32le(out, (uint32_t)st->msg_len);
    memcpy(out + 4, st->msg, st->msg_len);
    memcpy(out + 4 + st->msg_len, st->com, HM_COM_BYTES);
    memcpy(out + 4 + st->msg_len + HM_COM_BYTES, st->r, HM_R_BYTES);
}

int blind_read_user_state(const uint8_t *buf, size_t len, blind_user_state *out)
{
    if (len < 4 + (size_t)HM_COM_BYTES + HM_R_BYTES)
        return 0;
    const size_t msg_len = get_u32le(buf);
    if (len != 4 + msg_len + HM_COM_BYTES + HM_R_BYTES)
        return 0;

    out->msg = NULL;
    out->msg_len = msg_len;
    if (msg_len > 0)
    {
        out->msg = malloc(msg_len);
        if (!out->msg)
            return 0;
        memcpy(out->msg, buf + 4, msg_len);
    }
    memcpy(out->com, buf + 4 + msg_len, HM_COM_BYTES);
    memcpy(out->r, buf + 4 + msg_len + HM_COM_BYTES, HM_R_BYTES);
    return 1;
}

void blind_user_state_free(blind_user_state *st)
{
    free(st->msg);
    st->msg = NULL;
    st->msg_len = 0;
}
