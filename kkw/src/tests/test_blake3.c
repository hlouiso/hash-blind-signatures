#include "../blake3_th.h"
#include "../shared.h"
#include "../xmss.h"
#include "../MPC_prove_functions.h"
#include "../MPC_verify_functions.h"

#include "test_rng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { int ok_=(c); printf("  %s %s\n", ok_?"ok  ":"FAIL",(m)); if(!ok_)failures++; } while(0)

static int hex2bin(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* Independent reference using only the pinned upstream API. */
static void reference_th(const uint8_t *domain, size_t domain_len,
                         const uint8_t *data, size_t data_len, uint8_t out[32])
{
    const uint8_t frame[4] = {
        (uint8_t)domain_len, (uint8_t)(domain_len >> 8),
        (uint8_t)(domain_len >> 16), (uint8_t)(domain_len >> 24)
    };
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "blind-mss tweakable hash v2");
    blake3_hasher_update(&h, frame, sizeof frame);
    if (domain_len) blake3_hasher_update(&h, domain, domain_len);
    if (data_len) blake3_hasher_update(&h, data, data_len);
    blake3_hasher_finalize(&h, out, 32);
}

static void root_digest(const uint8_t *in, size_t len, uint8_t out32[32])
{
    uint32_t iv[8] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
                      0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
    uint32_t m[16] = {0}, cv[8];
    uint8_t block[64] = {0};
    memcpy(block, in, len);
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)block[4*i] | ((uint32_t)block[4*i+1] << 8)
             | ((uint32_t)block[4*i+2] << 16) | ((uint32_t)block[4*i+3] << 24);
    blake3_compress(iv, m, 0, (uint32_t)len,
                    BLAKE3_CHUNK_START | BLAKE3_CHUNK_END | BLAKE3_ROOT, cv);
    for (int i = 0; i < 8; i++) {
        out32[i*4+0] = (uint8_t)(cv[i]);
        out32[i*4+1] = (uint8_t)(cv[i] >> 8);
        out32[i*4+2] = (uint8_t)(cv[i] >> 16);
        out32[i*4+3] = (uint8_t)(cv[i] >> 24);
    }
}

static void test_vectors(void)
{
    printf("--- Test 1: compress vs official BLAKE3 vectors ---\n");
    static const struct { size_t len; const char *hex; } V[] = {
        {  0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
        {  1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" },
        { 33, "4f4e6c1dffd3a6c9959876d15aa96b5fb0da8632b995f6ca2e30503f2829fa29" },
        { 64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98" },
    };
    uint8_t in[64], got[32], want[32];
    for (int i = 0; i < 64; i++) in[i] = (uint8_t)(i % 251);
    for (size_t t = 0; t < sizeof V / sizeof V[0]; t++) {
        root_digest(in, V[t].len, got);
        hex2bin(V[t].hex, want, 32);
        char msg[64];
        snprintf(msg, sizeof msg, "official vector, len=%zu", V[t].len);
        CHECK(memcmp(got, want, 32) == 0, msg);
    }
}

static void test_th(void)
{
    printf("--- Test 2: blake3_th structure ---\n");
    uint8_t a[32], b[32], data[130];
    test_random_bytes(data, sizeof data);

    blake3_th((const uint8_t *)"dom1", 4, data, 100, a, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 100, b, 32);
    CHECK(memcmp(a, b, 32) == 0, "deterministic");

    blake3_th((const uint8_t *)"dom2", 4, data, 100, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "domain separation");

    blake3_th((const uint8_t *)"dom1", 4, data, 99, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "length separation (block_len in compress)");

    blake3_th((const uint8_t *)"dom1", 4, data, 64, a, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 65, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "block-count separation");

    blake3_th((const uint8_t *)"dom1\0", 5, data, 100, b, 32);
    blake3_th((const uint8_t *)"dom1", 4, data, 100, a, 32);
    CHECK(memcmp(a, b, 32) != 0, "domain-length binding (D vs D||0x00)");

    blake3_th((const uint8_t *)"a", 1, (const uint8_t *)"bc", 2, a, 32);
    blake3_th((const uint8_t *)"ab", 2, (const uint8_t *)"c", 1, b, 32);
    CHECK(memcmp(a, b, 32) != 0, "length framing prevents ambiguous domain/data concatenation");

    uint8_t ext[64];
    test_random_bytes(ext, 64);
    blake3_th((const uint8_t *)"dom1", 4, data, 64, a, 32);
    uint8_t cat[128];
    memcpy(cat, data, 64); memcpy(cat + 64, ext, 64);
    blake3_th((const uint8_t *)"dom1", 4, cat, 128, b, 32);
    uint32_t st[8], em[16];
    for (int i = 0; i < 8; i++)
        st[i] = (uint32_t)a[4*i] | ((uint32_t)a[4*i+1] << 8)
              | ((uint32_t)a[4*i+2] << 16) | ((uint32_t)a[4*i+3] << 24);
    for (int i = 0; i < 16; i++)
        em[i] = (uint32_t)ext[4*i] | ((uint32_t)ext[4*i+1] << 8)
              | ((uint32_t)ext[4*i+2] << 16) | ((uint32_t)ext[4*i+3] << 24);
    blake3_compress(st, em, 0, 64,
                    BLAKE3_DERIVE_KEY_MATERIAL | BLAKE3_CHUNK_END | BLAKE3_ROOT, st);
    uint8_t extended[32];
    for (int i = 0; i < 8; i++) {
        extended[i*4+0] = (uint8_t)(st[i]);
        extended[i*4+1] = (uint8_t)(st[i] >> 8);
        extended[i*4+2] = (uint8_t)(st[i] >> 16);
        extended[i*4+3] = (uint8_t)(st[i] >> 24);
    }
    CHECK(memcmp(extended, b, 32) != 0, "not length-extendable (ROOT finalisation)");

    enum { TWEAK_BYTES = XMSS_PK_SEED_BYTES + XMSS_EPOCH_BYTES + 2 };
    uint8_t prev[XMSS_NODE_BYTES], dom_chain[XMSS_NODE_BYTES + 1];
    uint8_t tweak[TWEAK_BYTES];
    test_random_bytes(prev, sizeof prev); test_random_bytes(tweak, sizeof tweak);
    memcpy(dom_chain, prev, sizeof prev);
    dom_chain[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
    blake3_th(dom_chain, sizeof dom_chain, tweak, sizeof tweak, a, XMSS_NODE_BYTES);
    uint32_t cv[8], m[16] = {0};
    memcpy(cv, blake3_th_context_key, sizeof cv);
    uint8_t blk[64] = {0};
    blk[0] = sizeof dom_chain;
    memcpy(blk + 4, dom_chain, sizeof dom_chain);
    memcpy(blk + 4 + sizeof dom_chain, tweak, sizeof tweak);
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)blk[4*i] | ((uint32_t)blk[4*i+1] << 8)
             | ((uint32_t)blk[4*i+2] << 16) | ((uint32_t)blk[4*i+3] << 24);
    blake3_compress(cv, m, 0, 4 + sizeof dom_chain + sizeof tweak,
                    BLAKE3_DERIVE_KEY_MATERIAL | BLAKE3_CHUNK_START |
                    BLAKE3_CHUNK_END | BLAKE3_ROOT, cv);
    uint8_t direct[XMSS_NODE_BYTES];
    for (int i = 0; i < XMSS_NODE_WORDS; i++)
        xmss_node_store_word(direct, (size_t)i, cv[i]);
    CHECK(memcmp(a, direct, XMSS_NODE_BYTES) == 0,
          "framed chain step == one standard derive-key compression");
    reference_th(dom_chain, sizeof dom_chain, tweak, sizeof tweak, b);
    CHECK(memcmp(a, b, XMSS_NODE_BYTES) == 0,
          "chain step matches the upstream derive-key API");
}

static void build_domain_frame(const uint8_t *dom, size_t len, uint8_t frame[32])
{
    memset(frame, 0, 32);
    frame[0] = (uint8_t)len;
    memcpy(frame + 4, dom, len);
}

static void test_domains(void)
{
    printf("--- Test 2b: pairwise-distinct domain frames across call sites ---\n");

    uint8_t pk_seed[XMSS_PK_SEED_BYTES], node[XMSS_NODE_BYTES];
    test_random_bytes(pk_seed, sizeof pk_seed);
    test_random_bytes(node, sizeof node);
    const uint32_t epoch = 0x000002A5, level = 3, idx = 0x0042;

    enum { NXMSS = 6, NKKW = 12, NDOM = NXMSS + NKKW };
    uint8_t dom[NDOM][32], cv[NDOM][32];
    size_t len[NDOM];
    const char *name[NDOM] = { "chain", "tree", "leaf", "message", "HMy", "HMd" };

    memcpy(dom[0], node, XMSS_NODE_BYTES);
    dom[0][XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
    len[0] = XMSS_NODE_BYTES + 1;

    memcpy(dom[1], pk_seed, XMSS_PK_SEED_BYTES);
    dom[1][XMSS_PK_SEED_BYTES] = XMSS_TWEAK_TREE;
    dom[1][XMSS_PK_SEED_BYTES + 1] = (uint8_t)level;
    for (int b = 0; b < 4; b++)
        dom[1][XMSS_PK_SEED_BYTES + 2 + b] = (uint8_t)(idx >> (8 * b));
    len[1] = XMSS_PK_SEED_BYTES + 2 + 4;

    memcpy(dom[2], pk_seed, XMSS_PK_SEED_BYTES);
    dom[2][XMSS_PK_SEED_BYTES] = XMSS_TWEAK_LEAF;
    for (int b = 0; b < 4; b++)
        dom[2][XMSS_PK_SEED_BYTES + 1 + b] = (uint8_t)(epoch >> (8 * (3 - b)));
    len[2] = XMSS_PK_SEED_BYTES + 1 + XMSS_EPOCH_BYTES;

    memcpy(dom[3], dom[2], len[2]);
    dom[3][XMSS_PK_SEED_BYTES] = XMSS_TWEAK_MESSAGE;
    len[3] = len[2];

    memcpy(dom[4], "HMy", 3); len[4] = 3;
    memcpy(dom[5], "HMd", 3); len[5] = 3;

    const char *kkw_tags[NKKW] = {
        KKW_DOM_PPCOM, KKW_DOM_HJ, KKW_DOM_HPRIME, KKW_DOM_HOUT,
        KKW_DOM_HSTAR1, KKW_DOM_HSTAR2, KKW_DOM_HSTAR3, KKW_DOM_HSTAR,
        KKW_DOM_FS, KKW_DOM_GRIND, KKW_DOM_PRG, KKW_DOM_MHAT,
    };
    int kkw_len_ok = 1;
    for (int t = 0; t < NKKW; t++) {
        size_t l = strlen(kkw_tags[t]);

        if (l == XMSS_NODE_BYTES + 1 || l > 28) kkw_len_ok = 0;
        memset(dom[NXMSS + t], 0, 32);
        memcpy(dom[NXMSS + t], kkw_tags[t], l);
        len[NXMSS + t] = l;
        name[NXMSS + t] = kkw_tags[t];
    }
    CHECK(kkw_len_ok,
          "no KKW-layer tag has the chain-family length or exceeds 28 bytes");

    for (int i = 0; i < NDOM; i++) build_domain_frame(dom[i], len[i], cv[i]);

    int distinct = 1;
    for (int i = 0; i < NDOM && distinct; i++)
        for (int j = i + 1; j < NDOM && distinct; j++)
            if (memcmp(cv[i], cv[j], 32) == 0) {
                printf("  domain frame collision: %s vs %s\n", name[i], name[j]);
                distinct = 0;
            }
    CHECK(distinct, "all call-site domain frames pairwise distinct (XMSS + HM + KKW)");

    int adv_ok = 1;
    for (int j = 1; j < NDOM && adv_ok; j++) {
        uint8_t evil_cv[32];
        uint8_t evil_dom[XMSS_NODE_BYTES + 1] = {0};
        memcpy(evil_dom, dom[j],
               len[j] < XMSS_NODE_BYTES ? len[j] : XMSS_NODE_BYTES);
        evil_dom[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
        build_domain_frame(evil_dom, sizeof evil_dom, evil_cv);
        if (memcmp(evil_cv, cv[j], 32) == 0) {
            printf("  adversarial chain node collides with %s\n", name[j]);
            adv_ok = 0;
        }
    }
    CHECK(adv_ok, "witness-chosen chain node cannot reach another family's domain frame");
}

static void test_incremental(void)
{
    printf("--- Test 2c: incremental Th == one-shot Th ---\n");
    uint8_t data[16385];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i % 251);
    /* The length prefix and seven-byte domain shift block/chunk boundaries. */
    const size_t lens[] = { 0, 1, 52, 53, 54, 63, 64, 65, 127, 128, 130, 192, 300,
                           1012, 1013, 1014, 1023, 1024, 1025, 2048, 16385 };
    int all_ok = 1;
    for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        size_t n = lens[li];
        uint8_t ref[32], inc[32], upstream[32];
        blake3_th((const uint8_t *)"inctest", 7, data, n, ref, 32);
        reference_th((const uint8_t *)"inctest", 7, data, n, upstream);
        if (memcmp(ref, upstream, 32) != 0) all_ok = 0;
        for (size_t cut = 0; cut <= n; cut++) {
            if (n > 300 && cut > 65 && cut != 1023 && cut != 1024 &&
                cut != 1025 && cut != n / 2 && cut != n - 1 && cut != n) continue;
            blake3_th_ctx c;
            blake3_th_init(&c, (const uint8_t *)"inctest", 7);
            blake3_th_update(&c, data, cut);
            blake3_th_update(&c, data + cut, n - cut);
            blake3_th_final(&c, inc, 32);
            if (memcmp(ref, inc, 32) != 0) all_ok = 0;
        }

        blake3_th_ctx c3;
        blake3_th_init(&c3, (const uint8_t *)"inctest", 7);
        blake3_th_update(&c3, data, n / 3);
        blake3_th_update(&c3, data + n / 3, n - n / 3 - n / 4);
        blake3_th_update(&c3, data + n - n / 4, n / 4);
        blake3_th_final(&c3, inc, 32);
        if (memcmp(ref, inc, 32) != 0) all_ok = 0;
        blake3_th_init(&c3, (const uint8_t *)"inctest", 7);
        for (size_t i = 0; i < n; i++) blake3_th_update(&c3, data + i, 1);
        blake3_th_final(&c3, inc, 32);
        if (memcmp(ref, inc, 32) != 0) all_ok = 0;
    }
    CHECK(all_ok, "native/incremental hashes match upstream across block/chunk boundaries");
}

static void test_bounds(void)
{
    printf("--- Test 2d: native API bounds ---\n");
    uint8_t domain[29] = {0}, out[64], untouched[64], expected[32];
    memset(untouched, 0xA5, sizeof untouched);
    memcpy(out, untouched, sizeof out);
    blake3_th_ctx ctx;
    CHECK(blake3_th_init(&ctx, domain, 28), "maximum domain length accepted");
    const size_t invalid_lengths[] = {33, 64, SIZE_MAX};
    for (size_t i = 0; i < sizeof invalid_lengths / sizeof invalid_lengths[0]; i++) {
        CHECK(!blake3_th_final(&ctx, out, invalid_lengths[i]) &&
              memcmp(out, untouched, sizeof out) == 0,
              "oversized output rejected without touching the destination");
    }
    CHECK(!blake3_th(domain, 28, NULL, 0, out, 33) &&
          memcmp(out, untouched, sizeof out) == 0,
          "one-shot API rejects oversized output");
    CHECK(blake3_th_final(&ctx, out, 32), "valid finalization after rejected output length");
    reference_th(domain, 28, NULL, 0, expected);
    CHECK(memcmp(out, expected, 32) == 0, "maximum domain matches upstream");
    CHECK(blake3_th_final(&ctx, out, 16) && memcmp(out, expected, 16) == 0,
          "repeated finalization and truncation match upstream");
    memcpy(out, untouched, sizeof out);
    CHECK(!blake3_th_init(&ctx, domain, 29) && !blake3_th_update(&ctx, NULL, 0) &&
          !blake3_th_final(&ctx, out, 32) && memcmp(out, untouched, sizeof out) == 0,
          "oversized domain poisons the context and produces no output");
    CHECK(!blake3_th(domain, 29, NULL, 0, out, 32) &&
          memcmp(out, untouched, sizeof out) == 0, "one-shot API rejects oversized domain");
    CHECK(!blake3_th(NULL, 1, NULL, 0, out, 32) &&
          memcmp(out, untouched, sizeof out) == 0, "NULL nonempty domain rejected");
    CHECK(blake3_th_init(&ctx, NULL, 0) && !blake3_th_update(&ctx, NULL, 1) &&
          !blake3_th_final(&ctx, out, 32) && memcmp(out, untouched, sizeof out) == 0,
          "NULL nonempty data poisons the context");
    CHECK(blake3_th(NULL, 0, NULL, 0, NULL, 0), "empty input and zero output accepted");
}

static void test_kkw_kat(void)
{
    printf("--- Test 2e: frozen KKW-domain derive-key v2 KAT ---\n");
    static const struct { const char *tag; const char *hex; } KAT[12] = {
        { "KKWppcom",  "6ba6d31a30787f5890944bc9b2432aeeaf6f69f63d6bc93040ea9edc90f2e537" },
        { "KKWhj",     "f08d75340cc442f8592eb8b7613e1f689e6177dc3c4108c4d181e325d5dade4b" },
        { "KKWhprime", "b39d55a4d5fe04fe3f8a40f24ffca84b270eab7745e06b18ec3a729f2893d813" },
        { "KKWhout",   "629cc00bd970175cacfd209f2424e5763d6bd47098c2a43aa4620d53e42ff361" },
        { "KKWhstar1", "4b70ed678ba89069c5b366a8bd3e71f0c5d732a8ee59677f2e72fab7303450c2" },
        { "KKWhstar2", "43fde92ffae25e73de393cb813c87d5b3c04a04965aeadb917668256f2c2b6c3" },
        { "KKWhstar3", "465bee6f31c4753d5a56d64b681e11e91d8c28c01fe66b4be841b1242d389c14" },
        { "KKWhstar",  "4f7f3255fe3feb3fd5ae9512bbd7cfe4d6eed70e086222b772d8963cc1588df5" },
        { "KKWfs",     "779991ec68fa681ec0d8367655402f1aa0963ad06b2b47b86028ff035502538e" },
        { "KKWgrind",  "545e8d207034a52f67d4385fd792144b913b33058d1315462292f83b580985a4" },
        { "KKWprg",    "7072298ee80dc8b83253267759aa6651696de0be77dd0b503b2cc8a8c880adfd" },
        { "KKWmhat",   "4c7968b58cf3bb8fc825cff14757fd955b98dd24f7169ce0ff6f00b6f79980ae" },
    };

    const char *tags_now[12] = {
        KKW_DOM_PPCOM, KKW_DOM_HJ, KKW_DOM_HPRIME, KKW_DOM_HOUT,
        KKW_DOM_HSTAR1, KKW_DOM_HSTAR2, KKW_DOM_HSTAR3, KKW_DOM_HSTAR,
        KKW_DOM_FS, KKW_DOM_GRIND, KKW_DOM_PRG, KKW_DOM_MHAT,
    };
    uint8_t data[200];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i % 251);
    int tags_ok = 1, kat_ok = 1;
    for (int t = 0; t < 12; t++) {
        if (strcmp(KAT[t].tag, tags_now[t]) != 0) tags_ok = 0;
        uint8_t expect[32], got[32];
        if (!hex2bin(KAT[t].hex, expect, 32)) { kat_ok = 0; continue; }
        blake3_th((const uint8_t *)tags_now[t], strlen(tags_now[t]),
                  data, sizeof data, got, 32);
        if (memcmp(got, expect, 32) != 0) kat_ok = 0;
    }
    CHECK(tags_ok, "the 12 KKW_DOM_* tags match the frozen KAT tags");
    CHECK(kat_ok, "Th(KKW_DOM_*, pattern) matches the frozen vectors");
}

static void test_mpc(int dom_len, int data_len, int out_len)
{
    printf("--- Test 3: MPC vs upstream (domain=%d data=%d output=%d) ---\n",
           dom_len, data_len, out_len);

    uint8_t dom[28], data[1024], want[32];
    test_random_bytes(dom, dom_len); test_random_bytes(data, data_len);
    reference_th(dom, (size_t)dom_len, data, (size_t)data_len, want);

    unsigned char seed_star[SEED_SIZE];
    test_random_bytes(seed_star, SEED_SIZE);
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds);
    unsigned char *tapes[N_PARTIES], *lamb[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        tapes[p] = malloc(TAPE_SIZE);
        lamb[p]  = malloc((size_t)(dom_len + data_len) + 1);
        expand_tape(seeds[p], tapes[p]);

        unsigned char xs[4096];
        expand_xshare(seeds[p], xs);
        memcpy(lamb[p], xs, dom_len + data_len);
    }

    unsigned char dom_pub[28], data_pub[1024];
    memcpy(dom_pub, dom, dom_len);
    memcpy(data_pub, data, data_len);
    for (int p = 0; p < N_PARTIES; p++) {
        for (int i = 0; i < dom_len; i++)  dom_pub[i]  ^= lamb[p][i];
        for (int i = 0; i < data_len; i++) data_pub[i] ^= lamb[p][dom_len + i];
    }
    unsigned char *dom_lam[N_PARTIES], *data_lam[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        dom_lam[p]  = lamb[p];
        data_lam[p] = lamb[p] + dom_len;
    }

    uint32_t *aux   = calloc((size_t)ySize, sizeof(uint32_t));
    uint32_t *s_all = calloc((size_t)N_PARTIES * ySize, sizeof(uint32_t));
    unsigned char out_pub[32], out_lam_buf[N_PARTIES][32];
    unsigned char *out_lam[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) out_lam[p] = out_lam_buf[p];

    int gc = 0;
    CHECK(mpc_blake3_th(dom_pub, dom_lam, dom_len, data_pub, data_lam, data_len,
                        out_pub, out_lam, out_len, tapes, aux, s_all, &gc),
          "prover accepts valid gadget sizes");
    printf("  (gadget gates: %d)\n", gc);

    unsigned char got[32];
    memcpy(got, out_pub, (size_t)out_len);
    for (int p = 0; p < N_PARTIES; p++)
        for (int i = 0; i < out_len; i++) got[i] ^= out_lam_buf[p][i];
    CHECK(memcmp(got, want, (size_t)out_len) == 0,
          "prove path unmasks to upstream derive-key hash");

    uint32_t *msgs_e   = malloc((size_t)ySize * sizeof(uint32_t));
    uint32_t *s_slots  = malloc((size_t)(N_PARTIES-1) * ySize * sizeof(uint32_t));
    for (int e = 0; e < N_PARTIES; e++) {
        for (int g2 = 0; g2 < gc; g2++)
            msgs_e[g2] = s_all[(size_t)e * ySize + (size_t)g2];
        unsigned char *vtapes[N_PARTIES-1], *vdlam[N_PARTIES-1], *vdatalam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) {
            int o = (j < e) ? j : j + 1;
            vtapes[j]   = tapes[o];
            vdlam[j]    = dom_lam[o];
            vdatalam[j] = data_lam[o];
        }
        unsigned char vout_pub[32], vout_lam_buf[N_PARTIES-1][32];
        unsigned char *vout_lam[N_PARTIES-1];
        for (int j = 0; j < N_PARTIES-1; j++) vout_lam[j] = vout_lam_buf[j];
        int vgc = 0;
        CHECK(mpc_blake3_th_verify(dom_pub, vdlam, dom_len, data_pub, vdatalam, data_len,
                                    vout_pub, vout_lam, out_len,
                                    vtapes, e, msgs_e, aux, s_slots, &vgc),
              "verifier accepts valid gadget sizes");
        char msg[64];
        snprintf(msg, sizeof msg, "verify path matches public output (e=%d)", e);
        int ok = (vgc == gc) && (memcmp(vout_pub, out_pub, (size_t)out_len) == 0);
        for (int j = 0; j < N_PARTIES-1 && ok; j++) {
            int o = (j < e) ? j : j + 1;
            if (memcmp(vout_lam[j], out_lam[o], (size_t)out_len) != 0) ok = 0;
        }

        for (int j = 0; j < N_PARTIES-1 && ok; j++) {
            int o = (j < e) ? j : j + 1;
            for (int g2 = 0; g2 < gc && ok; g2++)
                if (s_slots[(size_t)j * ySize + (size_t)g2] !=
                    s_all[(size_t)o * ySize + (size_t)g2]) ok = 0;
        }
        CHECK(ok, msg);
    }

    for (int p = 0; p < N_PARTIES; p++) { free(tapes[p]); free(lamb[p]); }
    free(aux); free(s_all); free(msgs_e); free(s_slots);
}

static void test_mpc_bounds(void)
{
    printf("--- Test 4: MPC API bounds ---\n");
    const int invalid[][3] = {
        {-1, 0, 32}, {29, 0, 32}, {0, -1, 32}, {0, 1021, 32},
        {28, 993, 32}, {0, 0, -1}, {0, 0, 33}
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        uint8_t out[32], untouched[32];
        memset(out, 0xA5, sizeof out);
        memcpy(untouched, out, sizeof out);
        int gc = 17;
        CHECK(!mpc_blake3_th(NULL, NULL, invalid[i][0], NULL, NULL, invalid[i][1],
                             out, NULL, invalid[i][2], NULL, NULL, NULL, &gc) &&
              gc == 17 && memcmp(out, untouched, sizeof out) == 0,
              "invalid prover sizes rejected before consuming gates or writing output");
        CHECK(!mpc_blake3_th_verify(NULL, NULL, invalid[i][0], NULL, NULL, invalid[i][1],
                                    out, NULL, invalid[i][2], NULL, 0, NULL, NULL, NULL, &gc) &&
              gc == 17 && memcmp(out, untouched, sizeof out) == 0,
              "invalid verifier sizes rejected before consuming gates or writing output");
    }
}

int main(void)
{
    ASSERT_LIB_PARAMS();
    test_vectors();
    test_th();
    test_domains();
    test_incremental();
    test_bounds();
    test_kkw_kat();
    const int mpc_cases[][3] = {
        {0, 0, 32}, {1, 0, 1}, {21, 0, 32}, {21, 38, 32}, {21, 39, 32},
        {21, 40, 32}, {21, 100, 32}, {3, 96, 32}, {3, 256, 32},
        {17, 22, 16}, {21, 56, 32}, {21, 672, 16}, {22, 32, 16},
        {0, 1020, 32}, {28, 992, 32}
    };
    for (size_t i = 0; i < sizeof mpc_cases / sizeof mpc_cases[0]; i++)
        test_mpc(mpc_cases[i][0], mpc_cases[i][1], mpc_cases[i][2]);
    test_mpc_bounds();
    printf("\n%s (%d failure%s)\n", failures?"FAILURES":"ALL PASS", failures, failures==1?"":"s");
    return failures ? 1 : 0;
}
