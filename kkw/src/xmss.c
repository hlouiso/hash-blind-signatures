#include "xmss.h"
#include "blake3_th.h"
#include "blake3_keyed_xof.h"
#include "randombytes.h"

#include <stdlib.h>
#include <string.h>

static void put_epoch_be(uint8_t *buf, size_t *o, uint32_t epoch)
{
    for (size_t k = 0; k < XMSS_EPOCH_BYTES; k++)
        buf[(*o)++] = (uint8_t)((epoch >> (8 * (XMSS_EPOCH_BYTES - 1 - k))) & 0xff);
}

void xmss_hash_message(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *nonce,
                       size_t nonce_len, const uint8_t *message, size_t message_len, uint8_t out32[32])
{
    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_MESSAGE;
    put_epoch_be(dom, &o, epoch);

    uint8_t *data = malloc(nonce_len + message_len);
    if (!data)
    {
        memset(out32, 0, 32);
        return;
    }
    memcpy(data, nonce, nonce_len);
    memcpy(data + nonce_len, message, message_len);
    blake3_th(dom, o, data, nonce_len + message_len, out32, 32);
    free(data);
}

void xmss_hash_chain_step(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node in,
                          uint8_t chain_idx, uint8_t pos, xmss_node out)
{

    uint8_t dom[XMSS_NODE_BYTES + 1];
    uint8_t data[XMSS_PK_SEED_BYTES + XMSS_EPOCH_BYTES + 1 + 1];
    memcpy(dom, in, XMSS_NODE_BYTES);
    dom[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
    size_t o = 0;
    memcpy(data + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    put_epoch_be(data, &o, epoch);
    data[o++] = chain_idx;
    data[o++] = pos;
    blake3_th(dom, sizeof dom, data, o, out, XMSS_NODE_BYTES);
}

void xmss_hash_chain_multi(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node start,
                           uint8_t chain_idx, uint8_t start_pos, uint8_t steps, xmss_node out)
{
    xmss_node cur;
    memcpy(cur, start, XMSS_NODE_BYTES);
    for (uint8_t i = 0; i < steps; i++)
    {
        uint8_t pos = (uint8_t)(start_pos + i + 1);
        xmss_node next;
        xmss_hash_chain_step(pk_seed, epoch, cur, chain_idx, pos, next);
        memcpy(cur, next, XMSS_NODE_BYTES);
    }
    memcpy(out, cur, XMSS_NODE_BYTES);
}

void xmss_hash_tree_node(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node left, const xmss_node right,
                         uint32_t level, uint32_t index, xmss_node out)
{

    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + 1 + 4];
    uint8_t data[2 * XMSS_NODE_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_TREE;
    dom[o++] = (uint8_t)(level & 0xff);
    for (int k = 0; k < 4; k++)
        dom[o++] = (uint8_t)((index >> (8 * k)) & 0xff);
    memcpy(data, left, XMSS_NODE_BYTES);
    memcpy(data + XMSS_NODE_BYTES, right, XMSS_NODE_BYTES);
    blake3_th(dom, o, data, sizeof data, out, XMSS_NODE_BYTES);
}

void xmss_hash_public_key(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node pk_hashes[XMSS_WOTS_LEN], xmss_node out)
{
    uint8_t dom[XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES];
    size_t o = 0;
    memcpy(dom + o, pk_seed, XMSS_PK_SEED_BYTES);
    o += XMSS_PK_SEED_BYTES;
    dom[o++] = XMSS_TWEAK_LEAF;
    put_epoch_be(dom, &o, epoch);
    blake3_th(dom, o, (const uint8_t *)pk_hashes,
              (size_t)XMSS_WOTS_LEN * XMSS_NODE_BYTES, out, XMSS_NODE_BYTES);
}

int xmss_extract_coords(const uint8_t hash[XMSS_MSG_HASH_LEN], uint8_t coords_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        const size_t pos = xmss_coord_bit_pos(i);
        uint8_t c = 0;
        for (int k = 0; k < XMSS_COORD_RES_BITS; k++)
        {
            const size_t j = pos + (size_t)k;
            c |= (uint8_t)(((hash[j / 8] >> (j % 8)) & 1u) << k);
        }
        coords_out[i] = c;
    }

    return ((hash[7] >> 7) | (hash[XMSS_MSG_HASH_LEN - 1] >> 7)) == 0;
}

void xmss_wots_gen_sk(const uint8_t sk_seed[32], uint32_t leaf_index, xmss_node sk_out[XMSS_WOTS_LEN])
{
    uint8_t leaf_be[4] = {
        (uint8_t)(leaf_index >> 24), (uint8_t)(leaf_index >> 16),
        (uint8_t)(leaf_index >> 8),  (uint8_t)leaf_index
    };

    blake3_keyed_xof(sk_seed, BLAKE3_XOF_DOM_XMSS_WOTS_SK,
                     leaf_be, sizeof leaf_be,
                     (uint8_t *)sk_out, sizeof(xmss_node) * XMSS_WOTS_LEN);
}

void xmss_wots_pk_from_sk(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                          const xmss_node sk[XMSS_WOTS_LEN], xmss_node pk_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        xmss_hash_chain_multi(pk_seed, epoch, sk[i], (uint8_t)i, 0, XMSS_WOTS_MAX_STEPS, pk_out[i]);
}

void xmss_wots_sign(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const xmss_node sk[XMSS_WOTS_LEN],
                    const uint8_t coords[XMSS_WOTS_LEN], xmss_node sig_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        if (coords[i] == 0)
            memcpy(sig_out[i], sk[i], XMSS_NODE_BYTES);
        else
            xmss_hash_chain_multi(pk_seed, epoch, sk[i], (uint8_t)i, 0, coords[i], sig_out[i]);
    }
}

void xmss_wots_pk_from_sig(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch,
                           const xmss_node sig[XMSS_WOTS_LEN], const uint8_t coords[XMSS_WOTS_LEN],
                           xmss_node pk_out[XMSS_WOTS_LEN])
{
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        uint8_t remaining = (uint8_t)(XMSS_WOTS_MAX_STEPS - coords[i]);
        if (remaining == 0)
            memcpy(pk_out[i], sig[i], XMSS_NODE_BYTES);
        else
            xmss_hash_chain_multi(pk_seed, epoch, sig[i], (uint8_t)i, coords[i], remaining, pk_out[i]);
    }
}

static void xmss_free_levels(xmss_node *tree[], int levels)
{
    for (int h = 0; h <= levels; h++)
    {
        free(tree[h]);
        tree[h] = NULL;
    }
}

static int xmss_alloc_levels(xmss_node *tree[], int levels)
{
    for (int h = 0; h <= levels; h++)
        tree[h] = NULL;
    for (int h = 0; h <= levels; h++)
    {
        size_t n = (size_t)1u << (levels - h);
        tree[h] = malloc(n * sizeof(xmss_node));
        if (!tree[h])
        {
            xmss_free_levels(tree, levels);
            return -1;
        }
    }
    return 0;
}

static void xmss_build_subtree(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                               uint32_t s, int subtree_h, xmss_node *sub[])
{
    size_t width = (size_t)1u << subtree_h;
    uint64_t base_epoch = (uint64_t)s << subtree_h;

#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (long long j = 0; j < (long long)width; j++)
    {
        uint32_t epoch = (uint32_t)(base_epoch + (uint64_t)j);
        xmss_node sk[XMSS_WOTS_LEN];
        xmss_node pk[XMSS_WOTS_LEN];
        xmss_wots_gen_sk(sk_seed, epoch, sk);
        xmss_wots_pk_from_sk(pk_seed, epoch, sk, pk);
        xmss_hash_public_key(pk_seed, epoch, pk, sub[0][j]);
    }

    for (int h = 1; h <= subtree_h; h++)
    {
        size_t n = (size_t)1u << (subtree_h - h);
        uint64_t base_index = (uint64_t)s << (subtree_h - h);
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
        for (long long j = 0; j < (long long)n; j++)
            xmss_hash_tree_node(pk_seed, sub[h - 1][2 * j], sub[h - 1][2 * j + 1], (uint32_t)(h - 1),
                                (uint32_t)(base_index + (uint64_t)j), sub[h][j]);
    }
}

static void xmss_build_top(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], int subtree_h, int top_h,
                           xmss_node *top[])
{
    for (int r = 1; r <= top_h; r++)
    {
        size_t n = (size_t)1u << (top_h - r);
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
        for (long long i = 0; i < (long long)n; i++)
            xmss_hash_tree_node(pk_seed, top[r - 1][2 * i], top[r - 1][2 * i + 1],
                                (uint32_t)(subtree_h + r - 1), (uint32_t)i, top[r][i]);
    }
}

static void xmss_derive_upper_siblings(const uint8_t sk_seed[32], int levels, xmss_node upper[])
{
    if (levels <= 0)
        return;
    blake3_keyed_xof(sk_seed, BLAKE3_XOF_DOM_XMSS_UPPER, NULL, 0,
                     (uint8_t *)upper, sizeof(xmss_node) * (size_t)levels);
}

static void xmss_climb_upper(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node real_root, int height,
                             const xmss_node upper[], xmss_node root_out)
{
    xmss_node node;
    memcpy(node, real_root, XMSS_NODE_BYTES);
    for (int i = 0; i < XMSS_H - height; i++)
    {
        xmss_node parent;
        xmss_hash_tree_node(pk_seed, node, upper[i], (uint32_t)(height + i), 0, parent);
        memcpy(node, parent, XMSS_NODE_BYTES);
    }
    memcpy(root_out, node, XMSS_NODE_BYTES);
}

struct xmss_keypair
{
    uint8_t sk_seed[32];
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    int height;
    int subtree_h;

    xmss_node *top[XMSS_H + 1];

    xmss_node *bottom[XMSS_H + 1];
    uint64_t cached_subtree;
    xmss_node upper[XMSS_H];
    xmss_node root;
};

#define XMSS_NO_SUBTREE UINT64_MAX

xmss_keypair *xmss_keypair_new(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                               int height)
{
    return xmss_keypair_new_split(sk_seed, pk_seed, height,
                                  height < XMSS_SUBTREE_H ? height : XMSS_SUBTREE_H);
}

xmss_keypair *xmss_keypair_new_split(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                                     int height, int subtree_h)
{
    if (height < 1 || height > XMSS_H)
        return NULL;
    if (subtree_h < 1 || subtree_h > height)
        return NULL;

    xmss_keypair *kp = malloc(sizeof *kp);
    if (!kp)
        return NULL;
    memcpy(kp->sk_seed, sk_seed, sizeof kp->sk_seed);
    memcpy(kp->pk_seed, pk_seed, XMSS_PK_SEED_BYTES);
    kp->height = height;
    kp->subtree_h = subtree_h;
    kp->cached_subtree = XMSS_NO_SUBTREE;
    const int top_h = height - kp->subtree_h;

    if (xmss_alloc_levels(kp->top, top_h) != 0)
    {
        free(kp);
        return NULL;
    }
    if (xmss_alloc_levels(kp->bottom, kp->subtree_h) != 0)
    {
        xmss_free_levels(kp->top, top_h);
        free(kp);
        return NULL;
    }

    for (uint64_t s = 0; s < (uint64_t)1u << top_h; s++)
    {
        xmss_build_subtree(kp->sk_seed, kp->pk_seed, (uint32_t)s, kp->subtree_h, kp->bottom);
        memcpy(kp->top[0][s], kp->bottom[kp->subtree_h][0], XMSS_NODE_BYTES);
    }

    kp->cached_subtree = top_h == 0 ? 0 : ((uint64_t)1u << top_h) - 1;

    xmss_build_top(kp->pk_seed, kp->subtree_h, top_h, kp->top);
    xmss_derive_upper_siblings(kp->sk_seed, XMSS_H - height, kp->upper);
    xmss_climb_upper(kp->pk_seed, kp->top[top_h][0], height, kp->upper, kp->root);
    return kp;
}

void xmss_keypair_free(xmss_keypair *kp)
{
    if (!kp)
        return;
    xmss_free_levels(kp->top, kp->height - kp->subtree_h);
    xmss_free_levels(kp->bottom, kp->subtree_h);

    volatile uint8_t *p = kp->sk_seed;
    for (size_t i = 0; i < sizeof kp->sk_seed; i++)
        p[i] = 0;
    free(kp);
}

void xmss_keypair_root(const xmss_keypair *kp, xmss_node root_out)
{
    memcpy(root_out, kp->root, XMSS_NODE_BYTES);
}

int xmss_keypair_height(const xmss_keypair *kp) { return kp->height; }

uint64_t xmss_keypair_capacity(const xmss_keypair *kp) { return (uint64_t)1u << kp->height; }

void xmss_compute_root(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], int height,
                       xmss_node root_out)
{
    xmss_keypair *kp = xmss_keypair_new(sk_seed, pk_seed, height);
    if (!kp)
    {
        memset(root_out, 0, XMSS_NODE_BYTES);
        return;
    }
    xmss_keypair_root(kp, root_out);
    xmss_keypair_free(kp);
}

static void xmss_walk_auth_path(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node leaf, uint32_t leaf_index,
                                const xmss_node auth_path[XMSS_H], xmss_node root_out)
{
    xmss_node node;
    memcpy(node, leaf, XMSS_NODE_BYTES);
    uint32_t idx = leaf_index;
    for (int h = 0; h < XMSS_H; h++)
    {
        xmss_node parent;
        if ((idx & 1) == 0)
            xmss_hash_tree_node(pk_seed, node, auth_path[h], (uint32_t)h, idx >> 1, parent);
        else
            xmss_hash_tree_node(pk_seed, auth_path[h], node, (uint32_t)h, idx >> 1, parent);
        memcpy(node, parent, XMSS_NODE_BYTES);
        idx >>= 1;
    }
    memcpy(root_out, node, XMSS_NODE_BYTES);
}

static int grind_nonce(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], uint32_t epoch, const uint8_t *message,
                       size_t message_len, uint8_t nonce_out[XMSS_NONCE_LEN], uint8_t coords_out[XMSS_WOTS_LEN])
{
    for (;;)
    {
        uint8_t nonce[XMSS_NONCE_LEN];
        if (!randombytes_fill(nonce, sizeof nonce))
            return 0;
        uint8_t mh[32];
        xmss_hash_message(pk_seed, epoch, nonce, XMSS_NONCE_LEN, message, message_len, mh);
        uint8_t coords[XMSS_WOTS_LEN];
        if (!xmss_extract_coords(mh, coords))
            continue;
        int sum = 0;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
            sum += coords[i];
        if (sum == XMSS_TARGET_SUM)
        {
            memcpy(nonce_out, nonce, XMSS_NONCE_LEN);
            memcpy(coords_out, coords, XMSS_WOTS_LEN);
            return 1;
        }
    }
}

int xmss_keypair_sign(xmss_keypair *kp, uint32_t leaf_index, const uint8_t *message, size_t message_len,
                      xmss_sig *out)
{

    if ((uint64_t)leaf_index >= xmss_keypair_capacity(kp))
        return 0;

    uint8_t coords[XMSS_WOTS_LEN];
    if (!grind_nonce(kp->pk_seed, leaf_index, message, message_len, out->nonce, coords))
        return 0;

    xmss_node sk[XMSS_WOTS_LEN];
    xmss_wots_gen_sk(kp->sk_seed, leaf_index, sk);
    xmss_wots_sign(kp->pk_seed, leaf_index, sk, coords, out->sig_hashes);

    const uint64_t s = (uint64_t)leaf_index >> kp->subtree_h;
    if (kp->cached_subtree != s)
    {
        xmss_build_subtree(kp->sk_seed, kp->pk_seed, (uint32_t)s, kp->subtree_h, kp->bottom);
        kp->cached_subtree = s;
    }

    uint64_t idx = leaf_index;
    for (int h = 0; h < kp->subtree_h; h++)
    {

        uint64_t base = s << (kp->subtree_h - h);
        memcpy(out->auth_path[h], kp->bottom[h][(idx ^ 1) - base], XMSS_NODE_BYTES);
        idx >>= 1;
    }

    for (int r = 0; r < kp->height - kp->subtree_h; r++)
    {
        memcpy(out->auth_path[kp->subtree_h + r], kp->top[r][idx ^ 1], XMSS_NODE_BYTES);
        idx >>= 1;
    }

    for (int h = kp->height; h < XMSS_H; h++)
        memcpy(out->auth_path[h], kp->upper[h - kp->height], XMSS_NODE_BYTES);

    out->leaf_index = leaf_index;
    return 1;
}

int xmss_sign(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES], int height,
              uint32_t leaf_index, const uint8_t *message, size_t message_len, xmss_sig *out)
{
    xmss_keypair *kp = xmss_keypair_new(sk_seed, pk_seed, height);
    if (!kp)
        return 0;
    int ok = xmss_keypair_sign(kp, leaf_index, message, message_len, out);
    xmss_keypair_free(kp);
    return ok;
}

int xmss_verify(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root, const uint8_t *message,
                size_t message_len, const xmss_sig *sig)
{
    uint8_t mh[32];
    xmss_hash_message(pk_seed, sig->leaf_index, sig->nonce, XMSS_NONCE_LEN, message, message_len, mh);
    uint8_t coords[XMSS_WOTS_LEN];

    if (!xmss_extract_coords(mh, coords))
        return 0;

    int sum = 0;
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        sum += coords[i];
    if (sum != XMSS_TARGET_SUM)
        return 0;

    xmss_node pk_hashes[XMSS_WOTS_LEN];
    xmss_wots_pk_from_sig(pk_seed, sig->leaf_index, sig->sig_hashes, coords, pk_hashes);

    xmss_node leaf;
    xmss_hash_public_key(pk_seed, sig->leaf_index, pk_hashes, leaf);

    xmss_node computed_root;
    xmss_walk_auth_path(pk_seed, leaf, sig->leaf_index, sig->auth_path, computed_root);

    return memcmp(computed_root, root, XMSS_NODE_BYTES) == 0;
}

void xmss_write_sig(const xmss_sig *sig, uint8_t out[XMSS_SIG_BYTES])
{
    size_t o = 0;
    for (int k = 0; k < 4; k++)
        out[o++] = (uint8_t)((sig->leaf_index >> (8 * k)) & 0xff);
    memcpy(out + o, sig->nonce, XMSS_NONCE_LEN);
    o += XMSS_NONCE_LEN;
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        memcpy(out + o, sig->sig_hashes[i], XMSS_NODE_BYTES);
        o += XMSS_NODE_BYTES;
    }
    for (int h = 0; h < XMSS_H; h++)
    {
        memcpy(out + o, sig->auth_path[h], XMSS_NODE_BYTES);
        o += XMSS_NODE_BYTES;
    }
}

int xmss_read_sig(const uint8_t *buf, size_t len, xmss_sig *out)
{
    if (len != XMSS_SIG_BYTES)
        return 0;

    size_t o = 0;
    out->leaf_index = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);
    o += 4;
    memcpy(out->nonce, buf + o, XMSS_NONCE_LEN);
    o += XMSS_NONCE_LEN;
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
    {
        memcpy(out->sig_hashes[i], buf + o, XMSS_NODE_BYTES);
        o += XMSS_NODE_BYTES;
    }
    for (int h = 0; h < XMSS_H; h++)
    {
        memcpy(out->auth_path[h], buf + o, XMSS_NODE_BYTES);
        o += XMSS_NODE_BYTES;
    }
    return 1;
}
