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
    blake3_compress(st, em, 0, 64, BLAKE3_ROOT, st);
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
    uint8_t tweak[TWEAK_BYTES], cv_bytes[32];
    test_random_bytes(prev, sizeof prev); test_random_bytes(tweak, sizeof tweak);
    memcpy(dom_chain, prev, sizeof prev);
    dom_chain[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
    blake3_th(dom_chain, sizeof dom_chain, tweak, sizeof tweak, a, XMSS_NODE_BYTES);
    uint32_t cv[8], m[16] = {0};
    memset(cv_bytes, 0, 32); memcpy(cv_bytes, dom_chain, sizeof dom_chain);
    for (int i = 0; i < 8; i++)
        cv[i] = (uint32_t)cv_bytes[4*i] | ((uint32_t)cv_bytes[4*i+1] << 8)
              | ((uint32_t)cv_bytes[4*i+2] << 16) | ((uint32_t)cv_bytes[4*i+3] << 24);
    cv[7] = XMSS_NODE_BYTES + 1;
    uint8_t blk[64] = {0}; memcpy(blk, tweak, sizeof tweak);
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)blk[4*i] | ((uint32_t)blk[4*i+1] << 8)
             | ((uint32_t)blk[4*i+2] << 16) | ((uint32_t)blk[4*i+3] << 24);
    blake3_compress(cv, m, 0, sizeof tweak, BLAKE3_ROOT, cv);
    uint8_t direct[XMSS_NODE_BYTES];
    for (int i = 0; i < XMSS_NODE_WORDS; i++)
        xmss_node_store_word(direct, (size_t)i, cv[i]);
    CHECK(memcmp(a, direct, XMSS_NODE_BYTES) == 0,
          "chain step == single compression");
}

static void build_cv(const uint8_t *dom, size_t len, uint8_t cv[32])
{
    memset(cv, 0, 32);
    memcpy(cv, dom, len);
    cv[28] = (uint8_t)len;
}

static void test_domains(void)
{
    printf("--- Test 2b: pairwise-distinct chaining values across call sites ---\n");

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

    for (int i = 0; i < NDOM; i++) build_cv(dom[i], len[i], cv[i]);

    int distinct = 1;
    for (int i = 0; i < NDOM && distinct; i++)
        for (int j = i + 1; j < NDOM && distinct; j++)
            if (memcmp(cv[i], cv[j], 32) == 0) {
                printf("  cv collision: %s vs %s\n", name[i], name[j]);
                distinct = 0;
            }
    CHECK(distinct, "all call-site cvs pairwise distinct (XMSS + HM + KKW layer)");

    int adv_ok = 1;
    for (int j = 1; j < NDOM && adv_ok; j++) {
        uint8_t evil_cv[32];
        uint8_t evil_dom[XMSS_NODE_BYTES + 1] = {0};
        memcpy(evil_dom, dom[j],
               len[j] < XMSS_NODE_BYTES ? len[j] : XMSS_NODE_BYTES);
        evil_dom[XMSS_NODE_BYTES] = XMSS_TWEAK_CHAIN;
        build_cv(evil_dom, sizeof evil_dom, evil_cv);
        if (memcmp(evil_cv, cv[j], 32) == 0) {
            printf("  adversarial chain node collides with %s\n", name[j]);
            adv_ok = 0;
        }
    }
    CHECK(adv_ok, "witness-chosen chain node cannot reach another family's cv");
}

static void test_incremental(void)
{
    printf("--- Test 2c: incremental Th == one-shot Th ---\n");
    uint8_t data[300];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i % 251);
    const size_t lens[] = { 0, 1, 63, 64, 65, 127, 128, 130, 192, 300 };
    int all_ok = 1;
    for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        size_t n = lens[li];
        uint8_t ref[32], inc[32];
        blake3_th((const uint8_t *)"inctest", 7, data, n, ref, 32);
        for (size_t cut = 0; cut <= n; cut++) {
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
    CHECK(all_ok, "init/update/final matches one-shot at all lengths and splits");

    uint8_t longdom[29] = {0}, z1[32], z2[32], zeros[32] = {0};
    blake3_th(longdom, 29, data, 10, z1, 32);
    blake3_th_ctx cp;
    blake3_th_init(&cp, longdom, 29);
    blake3_th_update(&cp, data, 10);
    blake3_th_final(&cp, z2, 32);
    CHECK(memcmp(z1, zeros, 32) == 0 && memcmp(z2, zeros, 32) == 0,
          "domain_len > 28 yields all-zero output on both APIs");
}

static void test_kkw_kat(void)
{
    printf("--- Test 2d: frozen KKW-domain KAT (format freeze) ---\n");
    static const struct { const char *tag; const char *hex; } KAT[12] = {
        { "KKWppcom",  "56dd77671c04694ec9719440a35c57820e24e5c07beff7c3753bdea241c29c27" },
        { "KKWhj",     "73fe6f43408dde3625af4b47d449bd5f68b8e6e8314568f68ca2d7bf7f9e7ca1" },
        { "KKWhprime", "a7c7180772965c0c8b7f7773cdc115652c5f925d68370042b1fe4f33e28d8a4b" },
        { "KKWhout",   "e29374e683ab42de51cf08075b780d812e4d76a587f6a0c819bf476ab3c76998" },
        { "KKWhstar1", "7a49f33d0c0cf33b4fb28604ef7bc54307b9b3e0aef696a9cbe0e9f308be3a36" },
        { "KKWhstar2", "42c796a146906ab532000d58336e76ab28f4a62d5e5e2a07dc3dd7f83bb5d7d0" },
        { "KKWhstar3", "3bdc3c3016f2e0cbe07c66d9bcfa714f3a05a7ea4d0fb62321d2042188d125f5" },
        { "KKWhstar",  "f35e620a7f9c3eb9d9dbf9c0003367a6ae66be2fde9e01886f81861c935738ba" },
        { "KKWfs",     "6d483d45eeb47ecbb71e1a19b6bab035d3b035a22d4bfca17c8ecbd069adb4f1" },
        { "KKWgrind",  "01eff4962b3f0b64a47cc24036793bad4f126ae02b55a13374a9b20d8f81a5e6" },
        { "KKWprg",    "ea2be5d38844c397a9469637ea3c0b58e82df09074ec9490d9a95f7d2314c089" },
        { "KKWmhat",   "85158b406504e572164d0929093fb0e5667415805fd4689d767cdd9df2eec780" },
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

static void test_mpc(void)
{
    printf("--- Test 3: mpc_blake3_th vs native (prove + verify paths) ---\n");

    const int dom_len = 21, data_len = 100;
    uint8_t dom[21], data[100], want[32];
    test_random_bytes(dom, dom_len); test_random_bytes(data, data_len);
    blake3_th(dom, dom_len, data, data_len, want, 32);

    unsigned char seed_star[SEED_SIZE];
    test_random_bytes(seed_star, SEED_SIZE);
    unsigned char seeds[N_PARTIES][SEED_SIZE];
    expand_seed_star(seed_star, seeds);
    unsigned char *tapes[N_PARTIES], *lamb[N_PARTIES];
    for (int p = 0; p < N_PARTIES; p++) {
        tapes[p] = malloc(TAPE_SIZE);
        lamb[p]  = malloc(dom_len + data_len);
        expand_tape(seeds[p], tapes[p]);

        unsigned char xs[4096];
        expand_xshare(seeds[p], xs);
        memcpy(lamb[p], xs, dom_len + data_len);
    }

    unsigned char dom_pub[21], data_pub[100];
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
    mpc_blake3_th(dom_pub, dom_lam, dom_len, data_pub, data_lam, data_len,
                  out_pub, out_lam, 32, tapes, aux, s_all, &gc);
    printf("  (gadget gates: %d)\n", gc);

    unsigned char got[32];
    memcpy(got, out_pub, 32);
    for (int p = 0; p < N_PARTIES; p++)
        for (int i = 0; i < 32; i++) got[i] ^= out_lam_buf[p][i];
    CHECK(memcmp(got, want, 32) == 0, "prove path unmasks to native blake3_th");

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
        mpc_blake3_th_verify(dom_pub, vdlam, dom_len, data_pub, vdatalam, data_len,
                             vout_pub, vout_lam, 32,
                             vtapes, e, msgs_e, aux, s_slots, &vgc);
        char msg[64];
        snprintf(msg, sizeof msg, "verify path matches public output (e=%d)", e);
        int ok = (vgc == gc) && (memcmp(vout_pub, out_pub, 32) == 0);

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

int main(void)
{
    ASSERT_LIB_PARAMS();
    test_vectors();
    test_th();
    test_domains();
    test_incremental();
    test_kkw_kat();
    test_mpc();
    printf("\n%s (%d failure%s)\n", failures?"FAILURES":"ALL PASS", failures, failures==1?"":"s");
    return failures ? 1 : 0;
}
