#include "xmss.h"
#include "hash.h"
#include "randombytes.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    shake_th(dom, o, data, nonce_len + message_len, out32, 32);
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
    shake_th(dom, sizeof dom, data, o, out, XMSS_NODE_BYTES);
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
    shake_th(dom, o, data, sizeof data, out, XMSS_NODE_BYTES);
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
    shake_th(dom, o, (const uint8_t *)pk_hashes,
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

    shake_keyed_xof(sk_seed, SHAKE_PRG_WOTS,
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

size_t xmss_threads(void)
{
    static size_t n;
    if (n == 0)
    {
        const char *s = getenv("XMSS_THREADS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0)
            v = sysconf(_SC_NPROCESSORS_ONLN);
        n = v > 0 ? (size_t)v : 1;
    }
    return n;
}

typedef void (*xmss_job_fn)(void *ctx, size_t i);

typedef struct
{
    xmss_job_fn fn;
    void *ctx;
    size_t n, chunk;
    atomic_size_t next;
} xmss_pool;

static void *xmss_pool_worker(void *arg)
{
    xmss_pool *p = arg;
    for (;;)
    {
        size_t first = atomic_fetch_add_explicit(&p->next, p->chunk, memory_order_relaxed);
        if (first >= p->n)
            return NULL;
        size_t last = first + p->chunk < p->n ? first + p->chunk : p->n;
        for (size_t i = first; i < last; i++)
            p->fn(p->ctx, i);
    }
}

/* fn(ctx, i) for i < n over up to `threads` threads. */
static void xmss_parallel_for(size_t n, size_t threads, xmss_job_fn fn, void *ctx)
{
    if (threads > n)
        threads = n;
    if (threads <= 1)
    {
        for (size_t i = 0; i < n; i++)
            fn(ctx, i);
        return;
    }
    size_t chunk = n / threads / 16;
    xmss_pool p = {fn, ctx, n, chunk < 1 ? 1 : (chunk > 64 ? 64 : chunk), 0};
    pthread_t *th = malloc((threads - 1) * sizeof *th);
    size_t started = 0;
    if (th)
        for (; started < threads - 1; started++)
            if (pthread_create(&th[started], NULL, xmss_pool_worker, &p) != 0)
                break;
    xmss_pool_worker(&p);
    for (size_t i = 0; i < started; i++)
        pthread_join(th[i], NULL);
    free(th);
}

typedef struct
{
    const uint8_t *sk_seed, *pk_seed;
    uint64_t base_epoch;
    xmss_node *leaves;
} xmss_leaf_job;

static void xmss_leaf(void *v, size_t j)
{
    const xmss_leaf_job *job = v;
    uint32_t epoch = (uint32_t)(job->base_epoch + (uint64_t)j);
    xmss_node sk[XMSS_WOTS_LEN];
    xmss_node pk[XMSS_WOTS_LEN];
    xmss_wots_gen_sk(job->sk_seed, epoch, sk);
    xmss_wots_pk_from_sk(job->pk_seed, epoch, sk, pk);
    xmss_hash_public_key(job->pk_seed, epoch, pk, job->leaves[j]);
}

static void xmss_build_subtree(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                               uint32_t s, int subtree_h, xmss_node *sub[], size_t threads)
{
    size_t width = (size_t)1u << subtree_h;
    uint64_t base_epoch = (uint64_t)s << subtree_h;

    xmss_leaf_job job = {sk_seed, pk_seed, base_epoch, sub[0]};
    xmss_parallel_for(width, threads, xmss_leaf, &job);

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
    shake_keyed_xof(sk_seed, SHAKE_PRG_UPPER, NULL, 0,
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

int xmss_cache_split_height(int height)
{
    return height <= 8 ? height : (height > 24 ? height - 16 : 8);
}

typedef struct
{
    const xmss_keypair *kp;
    atomic_int failed;
} xmss_root_job;

/* top[0][s], the root of bottom subtree s, with scratch levels of its own. */
static void xmss_subtree_root(void *v, size_t s)
{
    xmss_root_job *job = v;
    const xmss_keypair *kp = job->kp;
    xmss_node *sub[XMSS_H + 1];
    if (xmss_alloc_levels(sub, kp->subtree_h) != 0)
    {
        atomic_store(&job->failed, 1);
        return;
    }
    xmss_build_subtree(kp->sk_seed, kp->pk_seed, (uint32_t)s, kp->subtree_h, sub, 1);
    memcpy(kp->top[0][s], sub[kp->subtree_h][0], XMSS_NODE_BYTES);
    xmss_free_levels(sub, kp->subtree_h);
}

/* Allocates the levels of a key with the given shape; NULL on bad input. */
static xmss_keypair *xmss_keypair_alloc(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                                        int height, int subtree_h)
{
    if (height < 1 || height > XMSS_H || subtree_h < 1 || subtree_h > height)
        return NULL;
    xmss_keypair *kp = malloc(sizeof *kp);
    if (!kp)
        return NULL;
    memcpy(kp->sk_seed, sk_seed, sizeof kp->sk_seed);
    memcpy(kp->pk_seed, pk_seed, XMSS_PK_SEED_BYTES);
    kp->height = height;
    kp->subtree_h = subtree_h;
    kp->cached_subtree = XMSS_NO_SUBTREE;
    if (xmss_alloc_levels(kp->top, height - subtree_h) != 0)
    {
        free(kp);
        return NULL;
    }
    if (xmss_alloc_levels(kp->bottom, subtree_h) != 0)
    {
        xmss_free_levels(kp->top, height - subtree_h);
        free(kp);
        return NULL;
    }
    return kp;
}

xmss_keypair *xmss_keypair_new(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                               int height)
{
    return xmss_keypair_new_split(sk_seed, pk_seed, height,
                                  height < XMSS_SUBTREE_H ? height : XMSS_SUBTREE_H);
}

xmss_keypair *xmss_keypair_new_split(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                                     int height, int subtree_h)
{
    xmss_keypair *kp = xmss_keypair_alloc(sk_seed, pk_seed, height, subtree_h);
    if (!kp)
        return NULL;
    const int top_h = height - kp->subtree_h;

    /* One subtree uses every thread; many subtrees take one thread each. */
    if (top_h == 0)
    {
        xmss_build_subtree(kp->sk_seed, kp->pk_seed, 0, kp->subtree_h, kp->bottom, xmss_threads());
        memcpy(kp->top[0][0], kp->bottom[kp->subtree_h][0], XMSS_NODE_BYTES);
        kp->cached_subtree = 0;
    }
    else
    {
        xmss_root_job job = {kp, 0};
        xmss_parallel_for((size_t)1u << top_h, xmss_threads(), xmss_subtree_root, &job);
        if (atomic_load(&job.failed))
        {
            xmss_keypair_free(kp);
            return NULL;
        }
    }

    xmss_build_top(kp->pk_seed, kp->subtree_h, top_h, kp->top);
    xmss_derive_upper_siblings(kp->sk_seed, XMSS_H - height, kp->upper);
    xmss_climb_upper(kp->pk_seed, kp->top[top_h][0], height, kp->upper, kp->root);
    return kp;
}

size_t xmss_keypair_top_nodes(const xmss_keypair *kp)
{
    return ((size_t)2u << (kp->height - kp->subtree_h)) - 1;
}

int xmss_keypair_subtree_height(const xmss_keypair *kp) { return kp->subtree_h; }

void xmss_keypair_export_top(const xmss_keypair *kp, uint8_t *out)
{
    const int top_h = kp->height - kp->subtree_h;
    for (int r = 0; r <= top_h; r++)
    {
        size_t bytes = ((size_t)1u << (top_h - r)) * XMSS_NODE_BYTES;
        memcpy(out, kp->top[r], bytes);
        out += bytes;
    }
}

xmss_keypair *xmss_keypair_from_top(const uint8_t sk_seed[32], const uint8_t pk_seed[XMSS_PK_SEED_BYTES],
                                    int height, int subtree_h, const uint8_t *nodes, size_t len)
{
    xmss_keypair *kp = xmss_keypair_alloc(sk_seed, pk_seed, height, subtree_h);
    if (!kp)
        return NULL;
    const int top_h = height - subtree_h;
    if (len != xmss_keypair_top_nodes(kp) * XMSS_NODE_BYTES)
    {
        xmss_keypair_free(kp);
        return NULL;
    }
    memcpy(kp->top[0], nodes, ((size_t)1u << top_h) * XMSS_NODE_BYTES);
    xmss_build_top(kp->pk_seed, subtree_h, top_h, kp->top);
    const uint8_t *p = nodes;
    for (int r = 0; r <= top_h; r++)
    {
        size_t bytes = ((size_t)1u << (top_h - r)) * XMSS_NODE_BYTES;
        if (memcmp(kp->top[r], p, bytes) != 0)
        {
            xmss_keypair_free(kp);
            return NULL;
        }
        p += bytes;
    }
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
        xmss_build_subtree(kp->sk_seed, kp->pk_seed, (uint32_t)s, kp->subtree_h, kp->bottom, xmss_threads());
        /* Stored top levels of another key fail here. */
        if (memcmp(kp->bottom[kp->subtree_h][0], kp->top[0][s], XMSS_NODE_BYTES) != 0)
        {
            kp->cached_subtree = XMSS_NO_SUBTREE;
            return 0;
        }
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

int xmss_verify(const uint8_t pk_seed[XMSS_PK_SEED_BYTES], const xmss_node root, int height,
                const uint8_t *message, size_t message_len, const xmss_sig *sig)
{
    if (height < 1 || height > XMSS_H || (sig->leaf_index & xmss_leaf_index_mask(height)) != 0)
        return 0;
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
