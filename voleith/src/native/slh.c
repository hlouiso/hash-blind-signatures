#include "slh.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <KeccakP-1600-plain64.h>
#ifdef SLH_ARM_SHA3_X2
#include <KeccakP-1600-times2-SnP.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif
#endif

const slh_params SLH_SHAKE_128_24 = {"SLH-DSA-SHAKE-128-24", 22, 1, 22, 24, 6, 2, 21};
const slh_params SLH_TOY_W4 = {"toy-w4-d1", 6, 1, 6, 5, 6, 2, 5};
const slh_params SLH_TOY_W16 = {"toy-w16-d3", 6, 3, 2, 4, 5, 4, 5};

enum { WOTS_HASH = 0, WOTS_PK = 1, TREE = 2, FORS_TREE = 3, FORS_ROOTS = 4,
       WOTS_PRF = 5, FORS_PRF = 6 };

/* FORS subtrees at or above this height are split across threads. */
#define PAR_HEIGHT 10
#define RATE 136

uint32_t slh_w(const slh_params *p) { return 1u << p->lg_w; }
uint32_t slh_len1(const slh_params *p) { return (8 * SLH_N + p->lg_w - 1) / p->lg_w; }
uint32_t slh_len2(const slh_params *p) {
    uint32_t x = slh_len1(p) * (slh_w(p) - 1), lg = 0;
    while (x >>= 1) ++lg;
    return lg / p->lg_w + 1;
}
uint32_t slh_len(const slh_params *p) { return slh_len1(p) + slh_len2(p); }
uint32_t slh_csum_shift(const slh_params *p) { return (8 - (slh_len2(p) * p->lg_w) % 8) % 8; }
uint32_t slh_csum_bytes(const slh_params *p) { return (slh_len2(p) * p->lg_w + 7) / 8; }
uint32_t slh_md_bytes(const slh_params *p) { return (p->k * p->a + 7) / 8; }
uint32_t slh_tree_bytes(const slh_params *p) { return (p->h - p->hp + 7) / 8; }
uint32_t slh_leaf_bytes(const slh_params *p) { return (p->hp + 7) / 8; }
size_t slh_sig_bytes(const slh_params *p) {
    return (size_t)SLH_N * (1 + p->k * (1 + p->a) + p->h + p->d * slh_len(p));
}
int slh_params_ok(const slh_params *p) {
    return slh_md_bytes(p) + slh_tree_bytes(p) + slh_leaf_bytes(p) == p->m &&
           p->hp * p->d == p->h && p->h - p->hp <= 64 && p->hp <= 30 &&
           p->a <= 31 && p->lg_w <= 8 && p->m <= RATE;
}

/* ------------------------------------------------------------- Keccak */

typedef struct {
    KeccakP1600_plain64_state s;
    size_t pos;
} sponge;

static void sponge_init(sponge *sp) { memset(sp, 0, sizeof(*sp)); }

static void sponge_absorb(sponge *sp, const uint8_t *in, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        sp->s.A[sp->pos / 8] ^= (uint64_t)in[i] << (8 * (sp->pos % 8));
        if (++sp->pos == RATE) {
            KeccakP1600_plain64_Permute_24rounds(&sp->s);
            sp->pos = 0;
        }
    }
}

static void sponge_squeeze(sponge *sp, uint8_t *out, size_t n) {
    sp->s.A[sp->pos / 8] ^= (uint64_t)0x1f << (8 * (sp->pos % 8));
    sp->s.A[(RATE - 1) / 8] ^= (uint64_t)0x80 << (8 * ((RATE - 1) % 8));
    KeccakP1600_plain64_Permute_24rounds(&sp->s);
    for (size_t i = 0, at = 0; i < n; ++i, ++at) {
        if (at == RATE) {
            KeccakP1600_plain64_Permute_24rounds(&sp->s);
            at = 0;
        }
        out[i] = (uint8_t)(sp->s.A[at / 8] >> (8 * (at % 8)));
    }
}

void slh_shake256(const uint8_t *const *parts, const size_t *lens, size_t n,
                  uint8_t *out, size_t out_len) {
    sponge sp;
    sponge_init(&sp);
    for (size_t i = 0; i < n; ++i) sponge_absorb(&sp, parts[i], lens[i]);
    sponge_squeeze(&sp, out, out_len);
}

void slh_shake256_block_state(const uint8_t block[136], uint64_t state[25]) {
    sponge sp;
    sponge_init(&sp);
    sponge_absorb(&sp, block, RATE);
    memcpy(state, sp.s.A, 25 * sizeof(uint64_t));
}

/* ------------------------------------------------------------ threads */

typedef void (*job_fn)(void *ctx, size_t i);
typedef struct {
    job_fn fn;
    void *ctx;
    size_t n;
    atomic_size_t next;
} job;

static void *worker(void *arg) {
    job *j = arg;
    for (size_t i; (i = atomic_fetch_add_explicit(&j->next, 1, memory_order_relaxed)) < j->n;)
        j->fn(j->ctx, i);
    return NULL;
}

size_t slh_threads(void) {
    static size_t n;
    if (!n) {
        const char *s = getenv("SLH_THREADS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0) v = sysconf(_SC_NPROCESSORS_ONLN);
        n = v > 0 ? (size_t)v : 1;
    }
    return n;
}

static void parallel_for(size_t n, job_fn fn, void *ctx) {
    size_t t = slh_threads();
    if (t > n) t = n;
    job j = {fn, ctx, n, 0};
    if (t <= 1) {
        worker(&j);
        return;
    }
    pthread_t *th = malloc((t - 1) * sizeof(pthread_t));
    size_t started = 0;
    if (th)
        for (; started < t - 1; ++started)
            if (pthread_create(&th[started], NULL, worker, &j) != 0) break;
    worker(&j);
    for (size_t i = 0; i < started; ++i) pthread_join(th[i], NULL);
    free(th);
}

/* ------------------------------------------------------------ address */

typedef struct {
    uint8_t b[32];
} adrs;

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void set_layer(adrs *a, uint32_t l) { put32(a->b, l); }
static void set_tree(adrs *a, uint64_t t) {
    memset(a->b + 4, 0, 4);
    for (int i = 0; i < 8; ++i) a->b[8 + i] = (uint8_t)(t >> (56 - 8 * i));
}
static void set_type(adrs *a, uint32_t ty) { put32(a->b + 16, ty); }
static void set_type_and_clear(adrs *a, uint32_t ty) {
    set_type(a, ty);
    memset(a->b + 20, 0, 12);
}
static void set_keypair(adrs *a, uint32_t v) { put32(a->b + 20, v); }
static uint32_t keypair(const adrs *a) { return get32(a->b + 20); }
static void set_chain(adrs *a, uint32_t v) { put32(a->b + 24, v); }
static void set_height(adrs *a, uint32_t v) { put32(a->b + 24, v); }
static void set_hash(adrs *a, uint32_t v) { put32(a->b + 28, v); }
static void set_index(adrs *a, uint32_t v) { put32(a->b + 28, v); }

/* --------------------------------------------------------- primitives */

typedef struct {
    const slh_params *p;
    const uint8_t *pk_seed;
    int paired;
} ctx_t;

static int have_paired_keccak(void) {
#if defined(SLH_ARM_SHA3_X2) && defined(__APPLE__)
    int enabled = 0;
    size_t size = sizeof(enabled);
    return sysctlbyname("hw.optional.arm.FEAT_SHA3", &enabled, &size, NULL, 0) == 0 && enabled;
#elif defined(SLH_ARM_SHA3_X2) && defined(HWCAP_SHA3)
    return (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
#else
    return 0;
#endif
}

/* F, H, T_l and PRF: SHAKE256(PK.seed || ADRS || data, 8n). */
static void thash(const ctx_t *c, const adrs *a, const uint8_t *data, size_t len,
                  uint8_t out[SLH_N]) {
#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
    // Every PRF, F and H fits in one SHAKE256 rate block.
    if (len == SLH_N || len == 2 * SLH_N) {
        KeccakP1600_plain64_state state = {0};
        uint8_t *block = (uint8_t *)state.A;
        memcpy(block, c->pk_seed, SLH_N);
        memcpy(block + SLH_N, a->b, sizeof(a->b));
        memcpy(block + SLH_N + sizeof(a->b), data, len);
        block[SLH_N + sizeof(a->b) + len] = 0x1f;
        block[RATE - 1] = 0x80;
        KeccakP1600_plain64_Permute_24rounds(&state);
        memcpy(out, block, SLH_N);
        return;
    }
#endif
    sponge sp;
    sponge_init(&sp);
    sponge_absorb(&sp, c->pk_seed, SLH_N);
    sponge_absorb(&sp, a->b, 32);
    sponge_absorb(&sp, data, len);
    sponge_squeeze(&sp, out, SLH_N);
}

#ifdef SLH_ARM_SHA3_X2
// Interleave two one-block SHAKE inputs in XKCP's native lane layout.
// Inputs may alias outputs (in particular during WOTS chain iteration).
static uint64x2_t lane_pair(const uint8_t *x, const uint8_t *y) {
    uint64_t lo, hi;
    memcpy(&lo, x, sizeof(lo));
    memcpy(&hi, y, sizeof(hi));
    return vcombine_u64(vcreate_u64(lo), vcreate_u64(hi));
}

static void thash2(const ctx_t *c, const adrs a[2], const uint8_t *x, const uint8_t *y,
                   size_t len, uint8_t out[2][SLH_N]) {
    enum { seed_lanes = SLH_N / 8, address_lanes = sizeof(a->b) / 8,
           data_lane = seed_lanes + address_lanes };
    KeccakP1600times2_states state = {0};
    for (size_t j = 0; j < SLH_N / 8; ++j)
        state.A[j] = lane_pair(c->pk_seed + 8 * j, c->pk_seed + 8 * j);
    for (size_t j = 0; j < sizeof(a->b) / 8; ++j)
        state.A[seed_lanes + j] = lane_pair(a[0].b + 8 * j, a[1].b + 8 * j);
    for (size_t j = 0; j < len / 8; ++j)
        state.A[data_lane + j] = lane_pair(x + 8 * j, y + 8 * j);
    state.A[data_lane + len / 8] = vdupq_n_u64(0x1f);
    state.A[RATE / 8 - 1] = vdupq_n_u64(UINT64_C(0x8000000000000000));
    KeccakP1600times2_PermuteAll_24rounds(&state);
    uint64x2_t lo = vzip1q_u64(state.A[0], state.A[1]);
    uint64x2_t hi = vzip2q_u64(state.A[0], state.A[1]);
    memcpy(out[0], &lo, SLH_N);
    memcpy(out[1], &hi, SLH_N);
}
#endif

static void hpair(const ctx_t *c, const adrs *a, const uint8_t *l, const uint8_t *r,
                  uint8_t out[SLH_N]) {
    uint8_t buf[2 * SLH_N];
    memcpy(buf, l, SLH_N);
    memcpy(buf + SLH_N, r, SLH_N);
    thash(c, a, buf, sizeof(buf), out);
}

size_t slh_pure_message(const uint8_t *msg, size_t len, uint8_t *out) {
    out[0] = 0;
    out[1] = 0;
    if (len) memcpy(out + 2, msg, len);
    return len + 2;
}

void slh_h_msg(const slh_params *p, const uint8_t r[SLH_N],
               const uint8_t pk_seed[SLH_N], const uint8_t pk_root[SLH_N],
               const uint8_t *msg, size_t len, uint8_t *out) {
    const uint8_t *parts[4] = {r, pk_seed, pk_root, msg};
    const size_t lens[4] = {SLH_N, SLH_N, SLH_N, len};
    slh_shake256(parts, lens, 4, out, p->m);
}

static void prf_msg(const uint8_t sk_prf[SLH_N], const uint8_t opt_rand[SLH_N],
                    const uint8_t *msg, size_t len, uint8_t out[SLH_N]) {
    const uint8_t *parts[3] = {sk_prf, opt_rand, msg};
    const size_t lens[3] = {SLH_N, SLH_N, len};
    slh_shake256(parts, lens, 3, out, SLH_N);
}

/* Algorithm 4. */
static void base_2b(const uint8_t *x, uint32_t b, uint32_t out_len, uint32_t *out) {
    size_t in = 0;
    uint32_t bits = 0;
    uint64_t total = 0;
    for (uint32_t o = 0; o < out_len; ++o) {
        while (bits < b) {
            total = (total << 8) | x[in++];
            bits += 8;
        }
        bits -= b;
        out[o] = (uint32_t)((total >> bits) & ((1ull << b) - 1));
    }
}

void slh_wots_digits(const slh_params *p, const uint8_t msg[SLH_N], uint32_t *d) {
    const uint32_t w = slh_w(p), len1 = slh_len1(p);
    base_2b(msg, p->lg_w, len1, d);
    uint64_t csum = 0;
    for (uint32_t i = 0; i < len1; ++i) csum += w - 1 - d[i];
    csum <<= slh_csum_shift(p);
    uint8_t cb[8];
    for (int i = 0; i < 8; ++i) cb[i] = (uint8_t)(csum >> (56 - 8 * i));
    base_2b(cb + 8 - slh_csum_bytes(p), p->lg_w, slh_len2(p), d + len1);
}

static void wots_sk(const ctx_t *c, const uint8_t *sk_seed, const adrs *a,
                    uint32_t i, uint8_t out[SLH_N]) {
    adrs s = *a;
    set_type_and_clear(&s, WOTS_PRF);
    set_keypair(&s, keypair(a));
    set_chain(&s, i);
    thash(c, &s, sk_seed, SLH_N, out);
}

/* Algorithm 6. */
static void wots_pkgen(const ctx_t *c, const uint8_t *sk_seed, const adrs *a,
                       uint8_t out[SLH_N]) {
    const uint32_t len = slh_len(c->p), w = slh_w(c->p);
    uint8_t *tmp = malloc((size_t)len * SLH_N);
    if (!tmp) abort();
    uint32_t i = 0;
#ifdef SLH_ARM_SHA3_X2
    if (c->paired) {
        adrs sk[2] = {*a, *a}, chain[2] = {*a, *a};
        for (unsigned k = 0; k < 2; ++k) {
            set_type_and_clear(&sk[k], WOTS_PRF);
            set_keypair(&sk[k], keypair(a));
        }
        for (; i + 1 < len; i += 2) {
            uint8_t x[2][SLH_N];
            for (unsigned k = 0; k < 2; ++k) {
                set_chain(&sk[k], i + k);
                set_chain(&chain[k], i + k);
            }
            thash2(c, sk, sk_seed, sk_seed, SLH_N, x);
            for (uint32_t j = 0; j + 1 < w; ++j) {
                set_hash(&chain[0], j);
                set_hash(&chain[1], j);
                thash2(c, chain, x[0], x[1], SLH_N, x);
            }
            memcpy(tmp + (size_t)i * SLH_N, x, sizeof(x));
        }
    }
#endif
    for (; i < len; ++i) {
        uint8_t *x = tmp + (size_t)i * SLH_N;
        wots_sk(c, sk_seed, a, i, x);
        adrs s = *a;
        set_chain(&s, i);
        for (uint32_t j = 0; j + 1 < w; ++j) {
            set_hash(&s, j);
            thash(c, &s, x, SLH_N, x);
        }
    }
    adrs pk = *a;
    set_type_and_clear(&pk, WOTS_PK);
    set_keypair(&pk, keypair(a));
    thash(c, &pk, tmp, (size_t)len * SLH_N, out);
    free(tmp);
}

/* Algorithm 8. */
static void wots_pk_from_sig(const ctx_t *c, const uint8_t *sig, const uint8_t msg[SLH_N],
                             const adrs *a, slh_stats *st, uint8_t out[SLH_N]) {
    const uint32_t len = slh_len(c->p), w = slh_w(c->p);
    uint32_t *d = malloc(len * sizeof(uint32_t));
    uint8_t *tmp = malloc((size_t)len * SLH_N);
    if (!d || !tmp) abort();
    slh_wots_digits(c->p, msg, d);
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t *x = tmp + (size_t)i * SLH_N;
        memcpy(x, sig + (size_t)i * SLH_N, SLH_N);
        adrs s = *a;
        set_chain(&s, i);
        for (uint32_t j = d[i]; j + 1 < w; ++j) {
            set_hash(&s, j);
            thash(c, &s, x, SLH_N, x);
            if (st) ++st->f;
        }
    }
    adrs pk = *a;
    set_type_and_clear(&pk, WOTS_PK);
    set_keypair(&pk, keypair(a));
    if (st) ++st->t;
    thash(c, &pk, tmp, (size_t)len * SLH_N, out);
    free(d);
    free(tmp);
}

static adrs xmss_adrs(uint32_t layer, uint64_t tree) {
    adrs a;
    memset(&a, 0, sizeof(a));
    set_layer(&a, layer);
    set_tree(&a, tree);
    return a;
}

/* Every level of one XMSS tree, level z at offset 2^(hp+1) - 2^(hp+1-z). */
static size_t level_offset(uint32_t hp, uint32_t z) {
    return (((size_t)1 << (hp + 1)) - ((size_t)1 << (hp + 1 - z))) * SLH_N;
}

typedef struct {
    const ctx_t *c;
    const uint8_t *sk_seed;
    adrs base;
    uint8_t *prev, *next;
    uint32_t z;
} level_job;

static void leaf_job(void *v, size_t i) {
    level_job *j = v;
    adrs a = j->base;
    set_type_and_clear(&a, WOTS_HASH);
    set_keypair(&a, (uint32_t)i);
    wots_pkgen(j->c, j->sk_seed, &a, j->next + i * SLH_N);
}

static void node_job(void *v, size_t i) {
    level_job *j = v;
    adrs a = j->base;
    set_type_and_clear(&a, TREE);
    set_height(&a, j->z);
    set_index(&a, (uint32_t)i);
    hpair(j->c, &a, j->prev + 2 * i * SLH_N, j->prev + (2 * i + 1) * SLH_N,
          j->next + i * SLH_N);
}

static uint8_t *xmss_levels(const ctx_t *c, const uint8_t *sk_seed, uint32_t layer,
                            uint64_t tree) {
    const uint32_t hp = c->p->hp;
    uint8_t *lv = malloc(level_offset(hp, hp + 1));
    if (!lv) return NULL;
    level_job j = {c, sk_seed, xmss_adrs(layer, tree), NULL, lv, 0};
    parallel_for((size_t)1 << hp, leaf_job, &j);
    for (uint32_t z = 1; z <= hp; ++z) {
        j.prev = lv + level_offset(hp, z - 1);
        j.next = lv + level_offset(hp, z);
        j.z = z;
        const size_t n = (size_t)1 << (hp - z);
        if (n >= 4096) {
            parallel_for(n, node_job, &j);
        } else {
            for (size_t i = 0; i < n; ++i) node_job(&j, i);
        }
    }
    return lv;
}

/* The node at height z and index i of one XMSS tree (Algorithm 9). */
static void xmss_node(const ctx_t *c, const uint8_t *sk_seed, uint32_t layer, uint64_t tree,
                      uint32_t i, uint32_t z, uint8_t out[SLH_N]) {
    const size_t n = (size_t)1 << z;
    uint8_t *nodes = malloc(n * SLH_N);
    if (!nodes) abort();
    level_job j = {c, sk_seed, xmss_adrs(layer, tree), NULL, nodes, 0};
    for (size_t k = 0; k < n; ++k) {
        adrs a = j.base;
        set_type_and_clear(&a, WOTS_HASH);
        set_keypair(&a, (uint32_t)(((uint64_t)i << z) + k));
        wots_pkgen(c, sk_seed, &a, nodes + k * SLH_N);
    }
    for (uint32_t h = 1; h <= z; ++h)
        for (size_t k = 0; k < n >> h; ++k) {
            adrs a = j.base;
            set_type_and_clear(&a, TREE);
            set_height(&a, h);
            set_index(&a, (uint32_t)(((uint64_t)i << (z - h)) + k));
            hpair(c, &a, nodes + 2 * k * SLH_N, nodes + (2 * k + 1) * SLH_N, nodes + k * SLH_N);
        }
    memcpy(out, nodes, SLH_N);
    free(nodes);
}

typedef struct {
    const ctx_t *c;
    const uint8_t *sk_seed;
    uint32_t layer, z;
    uint8_t *out;
} subroot_job;

static void subroot(void *v, size_t i) {
    subroot_job *j = v;
    xmss_node(j->c, j->sk_seed, j->layer, 0, (uint32_t)i, j->z, j->out + i * SLH_N);
}

/* Levels first..hp of the top-layer tree, packed from height `first` up. */
static size_t top_offset(uint32_t hp, uint32_t first, uint32_t z) {
    return level_offset(hp, z) - level_offset(hp, first);
}

static uint8_t *top_levels(const ctx_t *c, const uint8_t *sk_seed, uint32_t first) {
    const uint32_t hp = c->p->hp, layer = c->p->d - 1;
    if (first == 0) return xmss_levels(c, sk_seed, layer, 0);
    uint8_t *lv = malloc(top_offset(hp, first, hp + 1));
    if (!lv) return NULL;
    subroot_job sj = {c, sk_seed, layer, first, lv};
    parallel_for((size_t)1 << (hp - first), subroot, &sj);
    level_job j = {c, sk_seed, xmss_adrs(layer, 0), NULL, NULL, 0};
    for (uint32_t z = first + 1; z <= hp; ++z) {
        j.prev = lv + top_offset(hp, first, z - 1);
        j.next = lv + top_offset(hp, first, z);
        j.z = z;
        const size_t n = (size_t)1 << (hp - z);
        if (n >= 4096) {
            parallel_for(n, node_job, &j);
        } else {
            for (size_t i = 0; i < n; ++i) node_job(&j, i);
        }
    }
    return lv;
}

/* Algorithm 10, with the authentication path given. */
static void xmss_sign(const ctx_t *c, const uint8_t msg[SLH_N], const uint8_t *sk_seed,
                      uint32_t idx, uint32_t layer, uint64_t tree, const uint8_t *auth,
                      uint8_t *out) {
    const slh_params *p = c->p;
    const uint32_t len = slh_len(p), w = slh_w(p);
    uint32_t *d = malloc(len * sizeof(uint32_t));
    if (!d) abort();
    slh_wots_digits(p, msg, d);
    adrs a = xmss_adrs(layer, tree);
    set_type_and_clear(&a, WOTS_HASH);
    set_keypair(&a, idx);
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t *x = out + (size_t)i * SLH_N;
        wots_sk(c, sk_seed, &a, i, x);
        adrs s = a;
        set_chain(&s, i);
        for (uint32_t k = 0; k < d[i] && k + 1 < w; ++k) {
            set_hash(&s, k);
            thash(c, &s, x, SLH_N, x);
        }
    }
    free(d);
    memcpy(out + (size_t)len * SLH_N, auth, (size_t)p->hp * SLH_N);
}

/* Algorithm 11. */
static void xmss_pk_from_sig(const ctx_t *c, uint32_t idx, const uint8_t *sig,
                             const uint8_t msg[SLH_N], uint32_t layer, uint64_t tree,
                             slh_stats *st, uint8_t out[SLH_N]) {
    const slh_params *p = c->p;
    const uint32_t len = slh_len(p);
    adrs a = xmss_adrs(layer, tree);
    set_type_and_clear(&a, WOTS_HASH);
    set_keypair(&a, idx);
    uint8_t node[SLH_N];
    wots_pk_from_sig(c, sig, msg, &a, st, node);
    set_type_and_clear(&a, TREE);
    for (uint32_t k = 0; k < p->hp; ++k) {
        const uint8_t *auth = sig + (size_t)(len + k) * SLH_N;
        set_height(&a, k + 1);
        set_index(&a, idx >> (k + 1));
        if (((idx >> k) & 1) == 0) hpair(c, &a, node, auth, node);
        else hpair(c, &a, auth, node, node);
        if (st) ++st->h;
    }
    memcpy(out, node, SLH_N);
}

/* Algorithm 14. */
static void fors_sk(const ctx_t *c, const uint8_t *sk_seed, const adrs *a, uint32_t idx,
                    uint8_t out[SLH_N]) {
    adrs s = *a;
    set_type_and_clear(&s, FORS_PRF);
    set_keypair(&s, keypair(a));
    set_index(&s, idx);
    thash(c, &s, sk_seed, SLH_N, out);
}

#ifdef SLH_ARM_SHA3_X2
// Compute two neighboring FORS subtrees together, pairing every PRF, F and H.
static void fors_node2(const ctx_t *c, const uint8_t *sk_seed, uint32_t i, uint32_t j,
                       uint32_t z, const adrs *base, uint8_t out[2][SLH_N]) {
    adrs a[2] = {*base, *base};
    if (z == 0) {
        for (unsigned k = 0; k < 2; ++k) {
            set_type_and_clear(&a[k], FORS_PRF);
            set_keypair(&a[k], keypair(base));
            set_index(&a[k], k == 0 ? i : j);
        }
        thash2(c, a, sk_seed, sk_seed, SLH_N, out);
        // Only the type changes from the leaf PRF to F (height is already zero).
        for (unsigned k = 0; k < 2; ++k) set_type(&a[k], FORS_TREE);
        thash2(c, a, out[0], out[1], SLH_N, out);
        return;
    }
    uint8_t left[2][SLH_N], right[2][SLH_N], children[2][2 * SLH_N];
    fors_node2(c, sk_seed, 2 * i, 2 * j, z - 1, base, left);
    fors_node2(c, sk_seed, 2 * i + 1, 2 * j + 1, z - 1, base, right);
    for (unsigned k = 0; k < 2; ++k) {
        set_height(&a[k], z);
        set_index(&a[k], k == 0 ? i : j);
        memcpy(children[k], left[k], SLH_N);
        memcpy(children[k] + SLH_N, right[k], SLH_N);
    }
    thash2(c, a, children[0], children[1], 2 * SLH_N, out);
}
#endif

/* Algorithm 15. */
static void fors_node(const ctx_t *c, const uint8_t *sk_seed, uint32_t i, uint32_t z,
                      const adrs *a, uint8_t out[SLH_N]) {
    adrs s = *a;
    if (z == 0) {
        uint8_t sk[SLH_N];
        fors_sk(c, sk_seed, a, i, sk);
        set_height(&s, 0);
        set_index(&s, i);
        thash(c, &s, sk, SLH_N, out);
        return;
    }
    uint8_t l[SLH_N], r[SLH_N];
#ifdef SLH_ARM_SHA3_X2
    if (c->paired) {
        uint8_t pair[2][SLH_N];
        fors_node2(c, sk_seed, 2 * i, 2 * i + 1, z - 1, a, pair);
        set_height(&s, z);
        set_index(&s, i);
        hpair(c, &s, pair[0], pair[1], out);
        return;
    }
#endif
    fors_node(c, sk_seed, 2 * i, z - 1, a, l);
    fors_node(c, sk_seed, 2 * i + 1, z - 1, a, r);
    set_height(&s, z);
    set_index(&s, i);
    hpair(c, &s, l, r, out);
}

typedef struct {
    const ctx_t *c;
    const uint8_t *sk_seed;
    const adrs *a;
    uint32_t base, z;
    uint8_t *out;
} fors_job;

static void fors_subtree_job(void *v, size_t j) {
    fors_job *f = v;
    fors_node(f->c, f->sk_seed, f->base + (uint32_t)j, f->z, f->a, f->out + j * SLH_N);
}

/* Node (i, z) of the FORS forest, split across threads when it is large. */
static void fors_node_par(const ctx_t *c, const uint8_t *sk_seed, uint32_t i, uint32_t z,
                          const adrs *a, uint8_t out[SLH_N]) {
    if (z < PAR_HEIGHT) {
        fors_node(c, sk_seed, i, z, a, out);
        return;
    }
    const uint32_t q = z < 8 ? z : 8, zs = z - q;
    size_t n = (size_t)1 << q;
    uint8_t *lv = malloc(n * SLH_N);
    if (!lv) abort();
    fors_job f = {c, sk_seed, a, i << q, zs, lv};
    parallel_for(n, fors_subtree_job, &f);
    for (uint32_t zz = zs + 1; zz <= z; ++zz) {
        for (size_t j = 0; j < n / 2; ++j) {
            adrs s = *a;
            set_height(&s, zz);
            set_index(&s, (i << (z - zz)) + (uint32_t)j);
            hpair(c, &s, lv + 2 * j * SLH_N, lv + (2 * j + 1) * SLH_N, lv + j * SLH_N);
        }
        n /= 2;
    }
    memcpy(out, lv, SLH_N);
    free(lv);
}

/* Algorithm 17. */
static void fors_pk_from_sig(const ctx_t *c, const uint8_t *sig, const uint8_t *md,
                             const adrs *a, slh_stats *st, uint8_t out[SLH_N]) {
    const slh_params *p = c->p;
    uint32_t *idx = malloc(p->k * sizeof(uint32_t));
    uint8_t *roots = malloc((size_t)p->k * SLH_N);
    if (!idx || !roots) abort();
    base_2b(md, p->a, p->k, idx);
    adrs s = *a;
    for (uint32_t i = 0; i < p->k; ++i) {
        const uint8_t *t = sig + (size_t)i * (1 + p->a) * SLH_N;
        const uint32_t leaf = (i << p->a) + idx[i];
        uint8_t node[SLH_N];
        set_height(&s, 0);
        set_index(&s, leaf);
        thash(c, &s, t, SLH_N, node);
        if (st) ++st->f;
        for (uint32_t j = 0; j < p->a; ++j) {
            const uint8_t *auth = t + (size_t)(1 + j) * SLH_N;
            set_height(&s, j + 1);
            set_index(&s, leaf >> (j + 1));
            if (((idx[i] >> j) & 1) == 0) hpair(c, &s, node, auth, node);
            else hpair(c, &s, auth, node, node);
            if (st) ++st->h;
        }
        memcpy(roots + (size_t)i * SLH_N, node, SLH_N);
    }
    adrs pk = *a;
    set_type_and_clear(&pk, FORS_ROOTS);
    set_keypair(&pk, keypair(a));
    if (st) ++st->t;
    thash(c, &pk, roots, (size_t)p->k * SLH_N, out);
    free(idx);
    free(roots);
}

static uint64_t to_int(const uint8_t *x, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | x[i];
    return v;
}
static uint64_t low_bits(uint64_t x, uint32_t bits) {
    return bits >= 64 ? x : x & ((1ull << bits) - 1);
}

static void split_digest(const slh_params *p, const uint8_t *digest, uint64_t *tree,
                         uint32_t *leaf) {
    const uint8_t *t = digest + slh_md_bytes(p);
    *tree = low_bits(to_int(t, slh_tree_bytes(p)), p->h - p->hp);
    *leaf = (uint32_t)low_bits(to_int(t + slh_tree_bytes(p), slh_leaf_bytes(p)), p->hp);
}

static adrs fors_adrs(uint64_t tree, uint32_t leaf) {
    adrs a = xmss_adrs(0, tree);
    set_type_and_clear(&a, FORS_TREE);
    set_keypair(&a, leaf);
    return a;
}

/* ---------------------------------------------------------------- key */

/* At h' = 22 the key keeps heights 6..22 of its top-layer tree, 2 MiB, and
 * a signature recomputes the 63 WOTS+ leaves below them on its path. */
struct slh_key {
    slh_params p;
    uint8_t sk_seed[SLH_N], sk_prf[SLH_N], pk_seed[SLH_N], pk_root[SLH_N];
    uint32_t first; /* the lowest stored height of the top-layer tree */
    uint8_t *top;   /* its levels first..hp, from the bottom up */
};

static uint32_t top_first(const slh_params *p) {
    const uint32_t over = p->hp > 16 ? p->hp - 16 : 0;
    return over < 6 ? over : 6;
}

slh_key *slh_keygen_internal(const slh_params *p, const uint8_t sk_seed[SLH_N],
                             const uint8_t sk_prf[SLH_N], const uint8_t pk_seed[SLH_N]) {
    if (!slh_params_ok(p)) return NULL;
    slh_key *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->p = *p;
    memcpy(k->sk_seed, sk_seed, SLH_N);
    memcpy(k->sk_prf, sk_prf, SLH_N);
    memcpy(k->pk_seed, pk_seed, SLH_N);
    const ctx_t c = {&k->p, k->pk_seed, have_paired_keccak()};
    k->first = top_first(p);
    k->top = top_levels(&c, k->sk_seed, k->first);
    if (!k->top) {
        free(k);
        return NULL;
    }
    memcpy(k->pk_root, k->top + top_offset(p->hp, k->first, p->hp), SLH_N);
    return k;
}

uint32_t slh_key_top_first(const slh_key *key) { return key->first; }

size_t slh_key_top_bytes(const slh_key *key) {
    return top_offset(key->p.hp, key->first, key->p.hp + 1);
}

void slh_key_export_top(const slh_key *key, uint8_t *out) {
    memcpy(out, key->top, slh_key_top_bytes(key));
}

typedef struct {
    const ctx_t *c;
    adrs base;
    const uint8_t *prev, *next;
    uint32_t z;
    atomic_int bad;
} check_job;

static void check_node(void *v, size_t i) {
    check_job *j = v;
    adrs a = j->base;
    set_type_and_clear(&a, TREE);
    set_height(&a, j->z);
    set_index(&a, (uint32_t)i);
    uint8_t node[SLH_N];
    hpair(j->c, &a, j->prev + 2 * i * SLH_N, j->prev + (2 * i + 1) * SLH_N, node);
    if (memcmp(node, j->next + i * SLH_N, SLH_N) != 0) atomic_store(&j->bad, 1);
}

slh_key *slh_key_from_top(const slh_params *p, const uint8_t sk_seed[SLH_N],
                          const uint8_t sk_prf[SLH_N], const uint8_t pk_seed[SLH_N],
                          const uint8_t pk_root[SLH_N], uint32_t first,
                          const uint8_t *levels, size_t len) {
    if (!slh_params_ok(p) || first > p->hp || len != top_offset(p->hp, first, p->hp + 1))
        return NULL;
    if (memcmp(levels + top_offset(p->hp, first, p->hp), pk_root, SLH_N) != 0) return NULL;
    slh_key *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->p = *p;
    memcpy(k->sk_seed, sk_seed, SLH_N);
    memcpy(k->sk_prf, sk_prf, SLH_N);
    memcpy(k->pk_seed, pk_seed, SLH_N);
    memcpy(k->pk_root, pk_root, SLH_N);
    k->first = first;
    const ctx_t c = {&k->p, k->pk_seed, 0};
    check_job j = {&c, xmss_adrs(p->d - 1, 0), NULL, NULL, 0, 0};
    for (uint32_t z = first + 1; z <= p->hp && !atomic_load(&j.bad); ++z) {
        j.prev = levels + top_offset(p->hp, first, z - 1);
        j.next = levels + top_offset(p->hp, first, z);
        j.z = z;
        parallel_for((size_t)1 << (p->hp - z), check_node, &j);
    }
    k->top = atomic_load(&j.bad) ? NULL : malloc(len);
    if (!k->top) {
        free(k);
        return NULL;
    }
    memcpy(k->top, levels, len);
    return k;
}

void slh_key_free(slh_key *key) {
    if (!key) return;
    free(key->top);
    memset(key, 0, sizeof(*key));
    free(key);
}

void slh_key_pk_seed(const slh_key *key, uint8_t out[SLH_N]) { memcpy(out, key->pk_seed, SLH_N); }
void slh_key_pk_root(const slh_key *key, uint8_t out[SLH_N]) { memcpy(out, key->pk_root, SLH_N); }

void slh_sign_internal(const slh_key *key, const uint8_t *msg, size_t len,
                       const uint8_t *addrnd, uint8_t *sig) {
    const slh_params *p = &key->p;
    const ctx_t c = {p, key->pk_seed, have_paired_keccak()};
    const uint32_t len_w = slh_len(p);
    uint8_t digest[RATE];
    prf_msg(key->sk_prf, addrnd ? addrnd : key->pk_seed, msg, len, sig);
    slh_h_msg(p, sig, key->pk_seed, key->pk_root, msg, len, digest);
    uint64_t tree;
    uint32_t leaf;
    split_digest(p, digest, &tree, &leaf);
    const adrs fa = fors_adrs(tree, leaf);

    /* Algorithm 16. */
    uint32_t *idx = malloc(p->k * sizeof(uint32_t));
    if (!idx) abort();
    base_2b(digest, p->a, p->k, idx);
    uint8_t *fors = sig + SLH_N;
    for (uint32_t i = 0; i < p->k; ++i) {
        uint8_t *t = fors + (size_t)i * (1 + p->a) * SLH_N;
        fors_sk(&c, key->sk_seed, &fa, (i << p->a) + idx[i], t);
        for (uint32_t j = 0; j < p->a; ++j)
            fors_node_par(&c, key->sk_seed, (i << (p->a - j)) + ((idx[i] >> j) ^ 1), j,
                          &fa, t + (size_t)(1 + j) * SLH_N);
    }
    free(idx);
    uint8_t node[SLH_N];
    fors_pk_from_sig(&c, fors, digest, &fa, NULL, node);

    /* Algorithm 12, reusing the cached top tree. */
    uint8_t *ht = fors + (size_t)p->k * (1 + p->a) * SLH_N;
    for (uint32_t j = 0; j < p->d; ++j) {
        if (j > 0) {
            leaf = (uint32_t)low_bits(tree, p->hp);
            tree = p->hp >= 64 ? 0 : tree >> p->hp;
        }
        const int top = j + 1 == p->d;
        const uint32_t first = top ? key->first : 0;
        uint8_t *lv = top ? key->top : xmss_levels(&c, key->sk_seed, j, tree);
        if (!lv) abort();
        uint8_t *auth = malloc((size_t)p->hp * SLH_N);
        if (!auth) abort();
        for (uint32_t z = 0; z < p->hp; ++z) {
            const uint32_t sibling = (leaf >> z) ^ 1;
            if (z < first)
                xmss_node(&c, key->sk_seed, j, tree, sibling, z, auth + (size_t)z * SLH_N);
            else
                memcpy(auth + (size_t)z * SLH_N,
                       lv + top_offset(p->hp, first, z) + (size_t)sibling * SLH_N, SLH_N);
        }
        uint8_t *out = ht + (size_t)j * (len_w + p->hp) * SLH_N;
        xmss_sign(&c, node, key->sk_seed, leaf, j, tree, auth, out);
        free(auth);
        memcpy(node, lv + top_offset(p->hp, first, p->hp), SLH_N);
        if (lv != key->top) free(lv);
    }
}

void slh_sign(const slh_key *key, const uint8_t *msg, size_t len, const uint8_t *addrnd,
              uint8_t *sig) {
    uint8_t *mp = malloc(len + 2);
    if (!mp) abort();
    slh_pure_message(msg, len, mp);
    slh_sign_internal(key, mp, len + 2, addrnd, sig);
    free(mp);
}

int slh_verify_internal(const slh_params *p, const uint8_t pk_seed[SLH_N],
                        const uint8_t pk_root[SLH_N], const uint8_t *msg, size_t len,
                        const uint8_t *sig, size_t sig_len, slh_stats *st) {
    if (!slh_params_ok(p) || sig_len != slh_sig_bytes(p)) return 0;
    const ctx_t c = {p, pk_seed, 0};
    const uint32_t len_w = slh_len(p);
    uint8_t digest[RATE], node[SLH_N];
    slh_h_msg(p, sig, pk_seed, pk_root, msg, len, digest);
    uint64_t tree;
    uint32_t leaf;
    split_digest(p, digest, &tree, &leaf);
    const adrs fa = fors_adrs(tree, leaf);
    const uint8_t *fors = sig + SLH_N;
    fors_pk_from_sig(&c, fors, digest, &fa, st, node);
    const uint8_t *ht = fors + (size_t)p->k * (1 + p->a) * SLH_N;
    for (uint32_t j = 0; j < p->d; ++j) {
        if (j > 0) {
            leaf = (uint32_t)low_bits(tree, p->hp);
            tree = p->hp >= 64 ? 0 : tree >> p->hp;
        }
        xmss_pk_from_sig(&c, leaf, ht + (size_t)j * (len_w + p->hp) * SLH_N, node, j, tree,
                         st, node);
    }
    return memcmp(node, pk_root, SLH_N) == 0;
}

int slh_verify(const slh_params *p, const uint8_t pk_seed[SLH_N],
               const uint8_t pk_root[SLH_N], const uint8_t *msg, size_t len,
               const uint8_t *sig, size_t sig_len) {
    uint8_t *mp = malloc(len + 2);
    if (!mp) return 0;
    slh_pure_message(msg, len, mp);
    const int ok = slh_verify_internal(p, pk_seed, pk_root, mp, len + 2, sig, sig_len, NULL);
    free(mp);
    return ok;
}
