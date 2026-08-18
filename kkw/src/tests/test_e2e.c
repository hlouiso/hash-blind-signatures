#include "../circuits.h"
#include "../commitment.h"
#include "../kkw_prove.h"
#include "../kkw_verify.h"
#include "../protocol.h"
#include "../shared.h"
#include "../xmss.h"

#include "test_rng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(c, m) do { \
    int check_ok_ = (c); \
    printf("  %s %s\n", check_ok_ ? "ok  " : "FAIL", (m)); \
    if (!check_ok_) failures++; \
} while (0)

static void run_parties(unsigned char input[W_END], unsigned char m_hat[32],
                        unsigned char pk_seed[XMSS_PK_SEED_BYTES], uint32_t pubout[8])
{

    unsigned char sk_seed[32];
    test_random_bytes(sk_seed, 32);
    test_random_bytes(pk_seed, XMSS_PK_SEED_BYTES);
    xmss_node root;
    xmss_compute_root(sk_seed, pk_seed, XMSS_TEST_H, root);

    test_random_bytes(m_hat, 32);
    unsigned char r[HM_R_BYTES], a_mat[HM_A_BYTES];
    test_random_bytes(r, sizeof r);
    test_random_bytes(a_mat, sizeof a_mat);
    unsigned char com[HM_COM_BYTES], d[32];
    hm_commit(m_hat, r, a_mat, com, d);

    xmss_sig sig;
    if (!xmss_sign(sk_seed, pk_seed, XMSS_TEST_H, 0, d, 32, &sig)) { printf("FAIL: xmss_sign\n"); exit(1); }
    if (!xmss_verify(pk_seed, root, d, 32, &sig))      { printf("FAIL: native verify\n"); exit(1); }

    memcpy(input + W_R_OFF, r, HM_R_BYTES);
    memcpy(input + W_A_OFF, a_mat, HM_A_BYTES);
    memset(input + W_LEAFIDX_OFF, 0, 4);
    memcpy(input + W_NONCE_OFF, sig.nonce, XMSS_NONCE_LEN);
    for (int i = 0; i < XMSS_WOTS_LEN; i++)
        memcpy(input + W_SIG_OFF + i * XMSS_NODE_BYTES, sig.sig_hashes[i], XMSS_NODE_BYTES);
    for (int h = 0; h < XMSS_H; h++)
        memcpy(input + W_PATH_OFF + h * XMSS_NODE_BYTES, sig.auth_path[h], XMSS_NODE_BYTES);

    memset(pubout, 0, 8 * sizeof(uint32_t));
    for (int w = 0; w < YP_ROOT_WORDS; w++)
        pubout[w] = xmss_node_load_word(root, (size_t)w);
    pubout[YP_SUM_WORD] = XMSS_TARGET_SUM;
}

int main(void)
{
    ASSERT_LIB_PARAMS();
    printf("--- End-to-end protocol (keygen→blind→sign→prove→verify) ---\n");
    kkw_verbose = 0;

    unsigned char input[W_END], m_hat[32], pk_seed[XMSS_PK_SEED_BYTES];
    uint32_t pubout[8];
    run_parties(input, m_hat, pk_seed, pubout);

    FILE *proof = tmpfile();
    if (!proof) { printf("FAIL: tmpfile\n"); return 1; }

    CHECK(kkw_prove(input, m_hat, pk_seed, pubout, proof) == 0, "prover produces a proof");

    rewind(proof);
    CHECK(kkw_verify(proof, m_hat, pk_seed, pubout) == 0, "verify accepts the honest proof");

    unsigned char bad_m[32];
    memcpy(bad_m, m_hat, 32);
    bad_m[0] ^= 0x01;
    rewind(proof);
    CHECK(kkw_verify(proof, bad_m, pk_seed, pubout) != 0, "verify rejects a wrong message");

    uint32_t bad_pubout[8];
    memcpy(bad_pubout, pubout, sizeof bad_pubout);
    bad_pubout[0] ^= 0x01;
    rewind(proof);
    CHECK(kkw_verify(proof, m_hat, pk_seed, bad_pubout) != 0, "verify rejects a forged public key");

    {
        fseek(proof, 0, SEEK_END);
        long plen = ftell(proof);
        rewind(proof);
        unsigned char *buf = malloc((size_t)plen);
        if (!buf || fread(buf, 1, (size_t)plen, proof) != (size_t)plen) {
            printf("FAIL: proof read-back\n"); return 1;
        }

        const long hdr_end     = 4 + 6*4 + 32 + 32 + 4;
        const long online_off  = hdr_end + (long)(M_KKW - NUM_ROUNDS) * 64;
        long offsets[14];
        int  n_off = 0;
        offsets[n_off++] = 4 + 6*4 + 3;
        offsets[n_off++] = 4 + 6*4 + 32 + 7;
        offsets[n_off++] = hdr_end - 2;
        offsets[n_off++] = hdr_end + 16;
        offsets[n_off++] = hdr_end + 40;
        offsets[n_off++] = online_off + 16;
        offsets[n_off++] = online_off + 32 + 4;
        offsets[n_off++] = online_off + 32 + (long)N_PARTIES*32 + 4;
        offsets[n_off++] = plen - 16;
        for (int i = 0; i < 5; i++) {
            uint32_t rnd;
            test_random_bytes((unsigned char *)&rnd, 4);
            offsets[n_off++] = online_off + (long)(rnd % (uint32_t)(plen - online_off));
        }

        int all_rejected = 1;
        FILE *tampered = tmpfile();
        if (!tampered) { printf("FAIL: tmpfile\n"); return 1; }
        for (int i = 0; i < n_off; i++) {
            buf[offsets[i]] ^= 0x01;
            rewind(tampered);
            if (fwrite(buf, 1, (size_t)plen, tampered) != (size_t)plen) {
                printf("FAIL: tamper write\n"); return 1;
            }
            rewind(tampered);
            if (kkw_verify(tampered, m_hat, pk_seed, pubout) == 0) {
                printf("  FAIL byte flip at offset %ld ACCEPTED\n", offsets[i]);
                all_rejected = 0;
            }
            buf[offsets[i]] ^= 0x01;
        }
        fclose(tampered);
        CHECK(all_rejected, "verify rejects every single-byte proof tampering (14 offsets, incl. yp/ke/r_j)");

        FILE *padded = tmpfile();
        if (!padded) { printf("FAIL: tmpfile\n"); return 1; }
        if (fwrite(buf, 1, (size_t)plen, padded) != (size_t)plen ||
            fputc(0x00, padded) == EOF) {
            printf("FAIL: padded write\n"); return 1;
        }
        rewind(padded);
        CHECK(kkw_verify(padded, m_hat, pk_seed, pubout) != 0,
              "verify rejects a proof with trailing data");
        fclose(padded);
        free(buf);
    }

    fclose(proof);

    {
        printf("--- Protocol API at leaf 3 ---\n");
        blind_signer_key key;
        xmss_node root;
        if (!blind_keygen(&key, XMSS_TEST_H, root)) { printf("FAIL: blind_keygen\n"); return 1; }
        key.next_leaf = 3;

        const char *msg = "a document to be blindly signed";
        const size_t msg_len = strlen(msg);
        blind_user_state st;
        if (!blind_user_commit((const unsigned char *)msg, msg_len, &st)) {
            printf("FAIL: blind_user_commit\n"); return 1;
        }

        xmss_sig sig2;
        CHECK(blind_signer_sign(&key, st.com, &sig2) == 1, "signer signs the commitment");
        CHECK(key.next_leaf == 4, "signing advances the leaf counter");
        CHECK(sig2.leaf_index == 3, "the signature is at the requested leaf");

        FILE *p2 = tmpfile();
        if (!p2) { printf("FAIL: tmpfile\n"); return 1; }
        CHECK(blind_user_prove(&st, key.pk_seed, root, &sig2, p2) == 0,
              "user proves at a non-zero leaf");
        rewind(p2);
        CHECK(blind_verify_sig(p2, (const unsigned char *)msg, msg_len, key.pk_seed, root) == 1,
              "verify accepts the honest proof at a non-zero leaf");

        rewind(p2);
        CHECK(blind_verify_sig(p2, (const unsigned char *)"another document", 16,
                               key.pk_seed, root) == 0,
              "verify rejects a different message");
        fclose(p2);
        blind_user_state_free(&st);
        blind_signer_key_free(&key);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILURES" : "ALL PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
