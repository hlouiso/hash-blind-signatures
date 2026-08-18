#include "xmss.h"

#include "test_rng.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg)                                                                                          \
    do                                                                                                            \
    {                                                                                                             \
        if (cond)                                                                                                 \
            printf("  ok   %s\n", msg);                                                                           \
        else                                                                                                      \
        {                                                                                                         \
            printf("  FAIL %s\n", msg);                                                                           \
            failures++;                                                                                           \
        }                                                                                                         \
    } while (0)

static int from_hex(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static const struct {
    const char *digest_hex;
    uint8_t coords[XMSS_WOTS_LEN];
    int leftover_ok;
    int sum;
} kEncodingVectors[] = {
    { "971f3566ad3fd575f6bf9699dfc2f17d", {7,2,6,7,1,2,5,1,6,4,5,6,2,7,7,1,5,2,7,2,7,6,6,7,7,3,5,5,4,1,3,6,7,5,5,0,6,1,6,7,6,7}, 1, 195 },
    { "77a8d6453a525f4cffbf2fecbfdf3e4b", {7,6,1,4,2,5,5,6,5,0,1,5,3,4,4,2,7,3,1,6,4,7,7,7,7,3,7,3,1,4,5,7,7,3,7,7,6,6,7,4,5,4}, 1, 195 },
    { "6cb4abdd5dba86439fdf9669d97eff7e", {4,5,1,2,3,7,2,5,5,3,7,6,5,4,6,5,6,0,6,1,4,7,3,6,7,5,5,5,4,1,5,5,4,5,5,7,3,7,7,3,7,7}, 1, 195 },
    { "fd5cf0f48ff1b749dbddff097afc5c7a", {5,7,3,6,5,0,4,7,4,6,7,7,0,3,4,7,7,6,6,4,4,3,3,7,6,5,7,7,7,1,1,0,5,7,0,7,7,4,3,1,5,7}, 1, 195 },
    { "004dab8b0c50fb0c01a98f974357defe", {0,0,4,6,4,6,2,5,3,1,2,6,0,0,4,2,3,7,3,6,0,1,0,4,4,2,7,3,4,7,2,6,1,4,6,5,2,6,3,3,7,7}, 0, 148 },
    { "3807a92b5d7610d9f2c55a7c246ba85c", {0,7,4,3,0,2,2,5,3,5,4,6,5,4,5,3,0,2,4,4,5,2,6,7,2,4,5,6,2,4,7,1,2,2,6,2,3,0,5,2,6,5}, 0, 152 },
    { "cdf9af0b35b13c3a6655773165e714d4", {5,1,7,4,7,7,3,5,3,1,4,2,3,2,4,5,4,7,0,5,3,6,4,5,2,5,6,5,3,1,6,4,2,6,6,1,7,4,2,0,2,5}, 0, 164 },
    { "b77215996f0bc725323951062956b656", {7,6,2,1,7,2,5,0,1,3,6,7,6,6,2,0,7,0,7,2,2,2,6,4,4,3,2,4,2,6,0,4,4,2,4,5,2,6,6,2,3,5}, 1, 155 },
    { "00000000000000000000000000000000", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 1, 0 },
    { "ffffffffffffffffffffffffffffffff", {7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7}, 0, 294 },
    { "58845db1462027f0d9c6bf1c9d7ac9a3", {0,3,1,2,0,3,7,2,1,6,2,3,4,0,0,1,7,4,0,0,7,1,3,3,3,4,7,7,5,4,3,4,6,1,5,6,3,1,1,7,1,2}, 0, 130 },
    { "b65c9fa346dff91728785b7ce60e53e3", {6,6,2,6,5,6,7,4,3,4,2,3,4,6,7,6,1,7,7,3,1,0,5,0,4,7,6,6,2,4,7,1,3,6,5,3,0,3,2,5,1,6}, 0, 172 },
    { "036e40178dfbf8deffe839d5f3c62db9", {3,0,0,7,6,0,0,2,7,2,4,6,0,7,6,7,0,7,3,7,5,7,7,3,4,6,3,6,1,5,2,7,1,7,5,1,6,5,5,4,4,3}, 0, 171 },
    { "9cc5744ec3d0b116b8196eba65336ba4", {4,3,6,2,4,1,5,3,6,1,5,1,4,1,4,6,1,6,2,3,1,0,7,6,4,1,4,3,3,2,7,6,2,6,6,4,1,3,5,1,2,2}, 0, 144 },
    { "149021e336e9359e626baa7330773505", {4,2,0,0,1,3,0,1,3,4,3,3,3,2,2,7,5,6,0,7,1,2,4,5,5,6,4,2,5,3,6,1,0,3,6,5,3,5,6,4,2,0}, 0, 134 },
    { "7bf340a276c03bf5b09ff145cb49dfd2", {3,7,5,1,7,1,0,2,2,4,2,3,7,0,0,6,3,7,4,2,7,0,6,6,7,1,3,4,7,5,0,5,5,4,3,2,2,7,3,3,1,5}, 0, 152 },
};

int main(void)
{
    uint8_t sk_seed[32];
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    test_random_bytes(sk_seed, sizeof sk_seed);
    test_random_bytes(pk_seed, sizeof pk_seed);

    xmss_node root1, root2;
    xmss_compute_root(sk_seed, pk_seed, XMSS_TEST_H, root1);
    xmss_compute_root(sk_seed, pk_seed, XMSS_TEST_H, root2);
    CHECK(memcmp(root1, root2, XMSS_NODE_BYTES) == 0, "root is deterministic in (sk_seed, pk_seed)");

    int nonzero = 0;
    for (int i = 0; i < XMSS_NODE_BYTES; i++)
        nonzero |= root1[i];
    CHECK(nonzero != 0, "root is non-zero");

    {
        xmss_node sk_a[XMSS_WOTS_LEN], sk_b[XMSS_WOTS_LEN], sk_c[XMSS_WOTS_LEN];
        xmss_wots_gen_sk(sk_seed, 7, sk_a);
        xmss_wots_gen_sk(sk_seed, 7, sk_b);
        xmss_wots_gen_sk(sk_seed, 8, sk_c);
        CHECK(memcmp(sk_a, sk_b, sizeof sk_a) == 0,
              "WOTS secret-key expansion is deterministic");
        CHECK(memcmp(sk_a, sk_c, sizeof sk_a) != 0,
              "WOTS secret-key expansion separates leaf indices");
    }

    {
        xmss_node sk[XMSS_WOTS_LEN], sig[XMSS_WOTS_LEN], pk_a[XMSS_WOTS_LEN], pk_b[XMSS_WOTS_LEN];
        uint8_t coords[XMSS_WOTS_LEN];
        const uint32_t epoch = 7;
        xmss_wots_gen_sk(sk_seed, epoch, sk);
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
        {
            uint8_t r;
            test_random_bytes(&r, 1);
            coords[i] = r & (uint8_t)(XMSS_WOTS_W - 1);
        }
        xmss_wots_sign(pk_seed, epoch, sk, coords, sig);
        xmss_wots_pk_from_sig(pk_seed, epoch, sig, coords, pk_a);
        xmss_wots_pk_from_sk(pk_seed, epoch, sk, pk_b);
        CHECK(memcmp(pk_a, pk_b, sizeof pk_a) == 0, "WOTS+ chain endpoints agree for random coords");
    }

    xmss_keypair *kp = xmss_keypair_new(sk_seed, pk_seed, XMSS_TEST_H);
    if (!kp)
    {
        printf("  FAIL could not build the key pair\n");
        return 1;
    }
    {
        xmss_node kp_root;
        xmss_keypair_root(kp, kp_root);
        CHECK(memcmp(kp_root, root1, XMSS_NODE_BYTES) == 0,
              "key-pair root matches xmss_compute_root");
    }

    const uint32_t leaves[] = {0, 1, 2, 511, 512, 1023};
    int all_valid = 1, all_target = 1, all_leftover = 1;
    for (size_t t = 0; t < sizeof leaves / sizeof leaves[0]; t++)
    {
        uint8_t msg[32];
        test_random_bytes(msg, sizeof msg);
        xmss_sig sig;
        int ok = xmss_keypair_sign(kp, leaves[t], msg, sizeof msg, &sig);
        if (!ok)
        {
            all_valid = 0;
            continue;
        }

        uint8_t mh[32], coords[XMSS_WOTS_LEN];
        xmss_hash_message(pk_seed, sig.leaf_index, sig.nonce, XMSS_NONCE_LEN, msg, sizeof msg, mh);
        if (!xmss_extract_coords(mh, coords))
            all_leftover = 0;
        int sum = 0;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
            sum += coords[i];
        if (sum != XMSS_TARGET_SUM)
            all_target = 0;

        if (!xmss_verify(pk_seed, root1, msg, sizeof msg, &sig))
            all_valid = 0;
    }
    CHECK(all_target, "grind always lands on the target sum");
    CHECK(all_leftover, "grind always clears both leftover top bits");
    CHECK(all_valid, "valid signatures verify at leaves 0,1,2,511,512,1023");

    {
        int all_ground = 1;
        for (uint32_t leaf = 0; leaf < 100; leaf++)
        {
            uint8_t msg[32];
            test_random_bytes(msg, sizeof msg);
            xmss_sig sig;
            if (!xmss_keypair_sign(kp, leaf, msg, sizeof msg, &sig) ||
                !xmss_verify(pk_seed, root1, msg, sizeof msg, &sig))
                all_ground = 0;
        }
        CHECK(all_ground, "grinding succeeds over 100 signatures");
    }

    CHECK(XMSS_WOTS_LEN == 42 && XMSS_NODE_BYTES == 16 && XMSS_H == 32 &&
              XMSS_NONCE_LEN == 24 && XMSS_PK_SEED_BYTES == 16,
          "signature shape: 42 chain starts of 16 B, 32 path nodes of 16 B, 24 B nonce");

    {

        uint8_t all_ones[XMSS_MSG_HASH_LEN], coords[XMSS_WOTS_LEN];
        memset(all_ones, 0xff, sizeof all_ones);
        int leftover_ok = xmss_extract_coords(all_ones, coords);
        int all_max = 1;
        for (int i = 0; i < XMSS_WOTS_LEN; i++)
            if (coords[i] != XMSS_WOTS_MAX_STEPS)
                all_max = 0;
        CHECK(all_max, "an all-ones digest decodes to all-maximal coordinates");
        CHECK(!leftover_ok, "a set leftover bit is rejected");

        uint8_t d[XMSS_MSG_HASH_LEN];
        memset(d, 0, sizeof d);
        CHECK(xmss_extract_coords(d, coords), "a clean digest is accepted");
        d[7] = 0x80;
        CHECK(!xmss_extract_coords(d, coords), "bit 63 alone is rejected");
        d[7] = 0;
        d[XMSS_MSG_HASH_LEN - 1] = 0x80;
        CHECK(!xmss_extract_coords(d, coords), "bit 127 alone is rejected");

        memset(d, 0, sizeof d);
        d[0] = 0xC0;
        d[1] = 0x01;
        xmss_extract_coords(d, coords);
        CHECK(coords[2] == 7, "a coordinate straddling a byte boundary decodes");

        memset(d, 0, sizeof d);
        d[8] = 0x05;
        xmss_extract_coords(d, coords);
        CHECK(coords[21] == 5 && coords[20] == 0,
              "the second digest word opens at coordinate 21");
    }

    {
        uint8_t msg[32];
        test_random_bytes(msg, sizeof msg);
        xmss_sig sig;
        if (!xmss_keypair_sign(kp, 42, msg, sizeof msg, &sig))
        {
            printf("  FAIL could not sign for negative tests\n");
            failures++;
        }
        else
        {
            CHECK(xmss_verify(pk_seed, root1, msg, sizeof msg, &sig), "baseline valid before tampering");

            xmss_sig bad = sig;
            bad.sig_hashes[3][0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "tampered sig_hash rejected");

            bad = sig;
            bad.auth_path[2][0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "tampered auth path rejected");

            bad = sig;
            bad.auth_path[XMSS_H - 1][0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad),
                  "tampered upper sibling rejected");

            bad = sig;
            bad.leaf_index ^= 1;
            CHECK(!xmss_verify(pk_seed, root1, msg, sizeof msg, &bad), "wrong leaf index rejected");

            uint8_t msg2[32];
            memcpy(msg2, msg, 32);
            msg2[0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, root1, msg2, sizeof msg2, &sig), "wrong message rejected");

            uint8_t other_root[XMSS_NODE_BYTES];
            memcpy(other_root, root1, XMSS_NODE_BYTES);
            other_root[0] ^= 0x01;
            CHECK(!xmss_verify(pk_seed, other_root, msg, sizeof msg, &sig), "wrong root rejected");
        }
    }

    {
        int vec_ok = 1;
        for (size_t v = 0; v < sizeof kEncodingVectors / sizeof kEncodingVectors[0]; v++)
        {
            uint8_t digest[XMSS_MSG_HASH_LEN], coords[XMSS_WOTS_LEN];
            if (!from_hex(kEncodingVectors[v].digest_hex, digest, sizeof digest))
            {
                vec_ok = 0;
                continue;
            }
            const int leftover_ok = xmss_extract_coords(digest, coords);
            int sum = 0;
            for (int i = 0; i < XMSS_WOTS_LEN; i++)
                sum += coords[i];
            if (memcmp(coords, kEncodingVectors[v].coords, XMSS_WOTS_LEN) != 0 ||
                leftover_ok != kEncodingVectors[v].leftover_ok ||
                sum != kEncodingVectors[v].sum)
            {
                printf("  vector %zu disagrees with binius64\n", v);
                vec_ok = 0;
            }
        }
        CHECK(vec_ok, "codeword extraction matches binius64's wots_encode");
    }

    {
        uint8_t msg[32];
        test_random_bytes(msg, sizeof msg);
        xmss_sig sig;

        if (!xmss_sign(sk_seed, pk_seed, XMSS_TEST_H, 137, msg, sizeof msg, &sig))
        {
            printf("  FAIL could not sign for serialization tests\n");
            failures++;
        }
        else
        {
            CHECK(XMSS_SIG_BYTES == 1212, "serialized signature is the minimal 1212 bytes");
            CHECK(XMSS_SIG_BYTES <= sizeof(xmss_sig), "wire form never exceeds the struct");

            uint8_t buf[XMSS_SIG_BYTES];
            xmss_write_sig(&sig, buf);

            xmss_sig got;
            CHECK(xmss_read_sig(buf, sizeof buf, &got), "round-trip parses");
            CHECK(got.leaf_index == sig.leaf_index, "round-trip preserves leaf_index");
            CHECK(memcmp(got.nonce, sig.nonce, XMSS_NONCE_LEN) == 0, "round-trip preserves nonce");
            CHECK(memcmp(got.sig_hashes, sig.sig_hashes, sizeof sig.sig_hashes) == 0,
                  "round-trip preserves sig_hashes");
            CHECK(memcmp(got.auth_path, sig.auth_path, sizeof sig.auth_path) == 0,
                  "round-trip preserves auth path");
            CHECK(xmss_verify(pk_seed, root1, msg, sizeof msg, &got),
                  "deserialized signature still verifies");

            uint8_t again[XMSS_SIG_BYTES];
            xmss_write_sig(&got, again);
            CHECK(memcmp(again, buf, XMSS_SIG_BYTES) == 0, "re-serialization is byte-identical");

            CHECK(buf[0] == (uint8_t)(sig.leaf_index & 0xff) && buf[1] == (uint8_t)(sig.leaf_index >> 8),
                  "leaf_index is little-endian on the wire");

            CHECK(!xmss_read_sig(buf, XMSS_SIG_BYTES - 1, &got), "short buffer rejected");
            uint8_t longer[XMSS_SIG_BYTES + 1];
            memcpy(longer, buf, XMSS_SIG_BYTES);
            longer[XMSS_SIG_BYTES] = 0;
            CHECK(!xmss_read_sig(longer, sizeof longer, &got), "trailing bytes rejected");

            uint8_t tampered[XMSS_SIG_BYTES];
            memcpy(tampered, buf, XMSS_SIG_BYTES);
            tampered[4 + XMSS_NONCE_LEN] ^= 0x01;
            CHECK(xmss_read_sig(tampered, sizeof tampered, &got) &&
                      !xmss_verify(pk_seed, root1, msg, sizeof msg, &got),
                  "tampered wire bytes parse but fail verification");
        }
    }

    xmss_keypair_free(kp);

    {
        int split_failures = 0;
        for (int height = 1; height <= 5 && !split_failures; height++)
        {

            xmss_node *flat[6] = {0};
            int alloc_ok = 1;
            for (int h = 0; h <= height; h++)
            {
                flat[h] = malloc(((size_t)1u << (height - h)) * sizeof(xmss_node));
                if (!flat[h])
                    alloc_ok = 0;
            }
            if (!alloc_ok)
            {
                printf("  FAIL out of memory building the reference tree\n");
                for (int h = 0; h <= height; h++)
                    free(flat[h]);
                split_failures++;
                break;
            }
            for (uint32_t l = 0; l < 1u << height; l++)
            {
                xmss_node sk[XMSS_WOTS_LEN], pk[XMSS_WOTS_LEN];
                xmss_wots_gen_sk(sk_seed, l, sk);
                xmss_wots_pk_from_sk(pk_seed, l, sk, pk);
                xmss_hash_public_key(pk_seed, l, pk, flat[0][l]);
            }
            for (int h = 1; h <= height; h++)
                for (uint32_t i = 0; i < 1u << (height - h); i++)
                    xmss_hash_tree_node(pk_seed, flat[h - 1][2 * i], flat[h - 1][2 * i + 1],
                                        (uint32_t)(h - 1), i, flat[h][i]);

            for (int subtree_h = 1; subtree_h <= height && !split_failures; subtree_h++)
            {
                xmss_keypair *split = xmss_keypair_new_split(sk_seed, pk_seed, height, subtree_h);
                if (!split)
                {
                    printf("  FAIL could not build h=%d sub=%d\n", height, subtree_h);
                    split_failures++;
                    break;
                }
                for (uint32_t leaf = 0; leaf < 1u << height && !split_failures; leaf++)
                {
                    uint8_t m[32];
                    memset(m, (uint8_t)leaf, sizeof m);
                    xmss_sig sig;
                    if (!xmss_keypair_sign(split, leaf, m, sizeof m, &sig))
                    {
                        printf("  FAIL sign h=%d sub=%d leaf %u\n", height, subtree_h, leaf);
                        split_failures++;
                        break;
                    }
                    uint32_t idx = leaf;
                    for (int h = 0; h < height; h++)
                    {
                        if (memcmp(sig.auth_path[h], flat[h][idx ^ 1], XMSS_NODE_BYTES) != 0)
                        {
                            printf("  FAIL sibling h=%d sub=%d leaf %u level %d\n", height, subtree_h,
                                   leaf, h);
                            split_failures++;
                            break;
                        }
                        idx >>= 1;
                    }
                    xmss_node split_root;
                    xmss_keypair_root(split, split_root);
                    if (!split_failures && !xmss_verify(pk_seed, split_root, m, sizeof m, &sig))
                    {
                        printf("  FAIL verify h=%d sub=%d leaf %u\n", height, subtree_h, leaf);
                        split_failures++;
                    }
                }
                xmss_keypair_free(split);
            }
            for (int h = 0; h <= height; h++)
                free(flat[h]);
        }
        CHECK(split_failures == 0,
              "the split traversal reproduces a materialized tree at every height and split");
    }

    printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILURES", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
