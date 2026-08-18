#include "protocol.h"

#include "kkw_prove.h"
#include "shared.h"
#include "xmss.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *g_dir = ".";

static void path_of(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/%s", g_dir, name);
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec * 1e-6;
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        fprintf(stderr, "error: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "error: cannot seek %s\n", path);
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    rewind(f);
    if (n < 0)
    {
        fprintf(stderr, "error: cannot size %s\n", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
    if (!buf || (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n))
    {
        fprintf(stderr, "error: cannot read %s\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        fprintf(stderr, "error: cannot open %s: %s\n", path, strerror(errno));
        return 0;
    }
    int ok = (len == 0) || (fwrite(buf, 1, len, f) == len);
    if (fclose(f) != 0)
        ok = 0;
    if (!ok)
        fprintf(stderr, "error: cannot write %s\n", path);
    return ok;
}

static void print_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: blindsig <command> [options]\n"
            "\n"
            "commands:\n"
            "  keygen                signer:   generate an XMSS key pair\n"
            "  commit <msg_file>     user:     commit to a message (round 1)\n"
            "  sign                  signer:   sign the commitment (round 1 reply)\n"
            "  prove                 user:     build the blind signature (round 2)\n"
            "  verify <msg_file>     verifier: check the blind signature\n"
            "\n"
            "options:\n"
            "  -d, --dir <path>      directory holding the artefacts (default \".\")\n"
            "      --height <h>      real XMSS tree height (keygen only, default %d, max %d).\n"
            "                        Keygen sweeps every one of the 2^h leaves and this CLI\n"
            "                        repeats that sweep on every invocation, so raising it\n"
            "                        costs time on both; the circuit climbs 32 levels either\n"
            "                        way.\n"
            "  -h, --help\n"
            "\n"
            "This binary is built for N=%d MPC parties, M=%d, tau=%d, W=%d grinding bits.\n",
            XMSS_H_DEFAULT, XMSS_H, N_PARTIES, M_KKW, NUM_ROUNDS, GRIND_W);
}

static int cmd_keygen(int height)
{
    char key_path[1024], pub_path[1024];
    path_of(key_path, sizeof key_path, "signer_key.bin");
    path_of(pub_path, sizeof pub_path, "signer_pub.bin");

    blind_signer_key key;
    xmss_node root;
    double t0 = now_ms();
    if (!blind_keygen(&key, height, root))
    {
        fprintf(stderr, "error: key generation failed (OS RNG)\n");
        return 1;
    }
    double keygen_ms = now_ms() - t0;

    uint8_t key_buf[BLIND_SIGNER_KEY_BYTES], pub_buf[BLIND_SIGNER_PUB_BYTES];
    blind_write_signer_key(&key, key_buf);
    blind_write_signer_pub(root, key.pk_seed, pub_buf);
    if (!write_file(key_path, key_buf, sizeof key_buf) ||
        !write_file(pub_path, pub_buf, sizeof pub_buf))
    {
        blind_signer_key_free(&key);
        return 1;
    }

    printf("keygen  ·  XMSS h=%d (%llu one-time signatures)  %.0f ms\n", key.height,
           (unsigned long long)1u << key.height,
           keygen_ms);
    printf("  root     : ");
    print_hex(root, XMSS_NODE_BYTES);
    printf("\n  pk_seed  : ");
    print_hex(key.pk_seed, XMSS_PK_SEED_BYTES);
    printf("\n  → signer_key.bin (%zu B, secret)\n", sizeof key_buf);
    printf("  → signer_pub.bin (%zu B)\n", sizeof pub_buf);
    blind_signer_key_free(&key);
    return 0;
}

static int cmd_commit(const char *msg_file)
{
    char com_path[1024], state_path[1024];
    path_of(com_path, sizeof com_path, "commitment.bin");
    path_of(state_path, sizeof state_path, "user_state.bin");

    size_t msg_len = 0;
    uint8_t *msg = read_file(msg_file, &msg_len);
    if (!msg)
        return 1;

    blind_user_state st;
    double t0 = now_ms();
    int ok = blind_user_commit(msg, msg_len, &st);
    double commit_ms = now_ms() - t0;
    free(msg);
    if (!ok)
    {
        fprintf(stderr, "error: commitment failed (OS RNG or allocation)\n");
        return 1;
    }

    const size_t state_len = blind_user_state_bytes(&st);
    uint8_t *state_buf = malloc(state_len);
    if (!state_buf)
    {
        blind_user_state_free(&st);
        fprintf(stderr, "error: out of memory\n");
        return 1;
    }
    blind_write_user_state(&st, state_buf);

    ok = write_file(com_path, st.com, HM_COM_BYTES) &&
         write_file(state_path, state_buf, state_len);
    free(state_buf);
    blind_user_state_free(&st);
    if (!ok)
        return 1;

    printf("commit  ·  message %zu B  %.1f ms\n", msg_len, commit_ms);
    printf("  → commitment.bin (%d B, send to the signer)\n", HM_COM_BYTES);
    printf("  → user_state.bin (%zu B, secret)\n", state_len);
    return 0;
}

static int cmd_sign(void)
{
    char key_path[1024], com_path[1024], sig_path[1024];
    path_of(key_path, sizeof key_path, "signer_key.bin");
    path_of(com_path, sizeof com_path, "commitment.bin");
    path_of(sig_path, sizeof sig_path, "xmss_sig.bin");

    size_t key_len = 0, com_len = 0;
    uint8_t *key_buf = read_file(key_path, &key_len);
    if (!key_buf)
        return 1;
    uint8_t *com_buf = read_file(com_path, &com_len);
    if (!com_buf)
    {
        free(key_buf);
        return 1;
    }

    blind_signer_key key;
    int ok = blind_read_signer_key(key_buf, key_len, &key);
    free(key_buf);
    if (!ok || com_len != HM_COM_BYTES)
    {
        fprintf(stderr, "error: malformed signer_key.bin or commitment.bin\n");
        free(com_buf);
        return 1;
    }

    const uint32_t leaf = key.next_leaf;
    xmss_sig sig;
    double t0 = now_ms();
    ok = blind_signer_sign(&key, com_buf, &sig);
    double sign_ms = now_ms() - t0;
    free(com_buf);
    if (!ok)
    {
        fprintf(stderr, "error: key exhausted or RNG failed\n");
        blind_signer_key_free(&key);
        return 1;
    }

    uint8_t sig_buf[XMSS_SIG_BYTES], new_key[BLIND_SIGNER_KEY_BYTES];
    xmss_write_sig(&sig, sig_buf);
    blind_write_signer_key(&key, new_key);
    if (!write_file(sig_path, sig_buf, sizeof sig_buf) ||
        !write_file(key_path, new_key, sizeof new_key))
    {
        blind_signer_key_free(&key);
        return 1;
    }

    printf("sign  ·  leaf %llu of %llu  %.0f ms\n", (unsigned long long)leaf,
           (unsigned long long)1u << key.height, sign_ms);
    printf("  → xmss_sig.bin (%zu B, send to the user)\n", sizeof sig_buf);
    printf("  signer_key.bin updated: next_leaf = %llu (%llu left)\n",
           (unsigned long long)key.next_leaf,
           (unsigned long long)(((uint64_t)1u << key.height) - key.next_leaf));
    blind_signer_key_free(&key);
    return 0;
}

static int cmd_prove(void)
{
    char state_path[1024], pub_path[1024], sig_path[1024], out_path[1024];
    path_of(state_path, sizeof state_path, "user_state.bin");
    path_of(pub_path, sizeof pub_path, "signer_pub.bin");
    path_of(sig_path, sizeof sig_path, "xmss_sig.bin");
    path_of(out_path, sizeof out_path, "blind_sig.bin");

    size_t state_len = 0, pub_len = 0, sig_len = 0;
    uint8_t *state_buf = read_file(state_path, &state_len);
    if (!state_buf)
        return 1;
    uint8_t *pub_buf = read_file(pub_path, &pub_len);
    uint8_t *sig_buf = pub_buf ? read_file(sig_path, &sig_len) : NULL;

    blind_user_state st = {0};
    xmss_node root;
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    xmss_sig sig;
    int ok = pub_buf && sig_buf && blind_read_user_state(state_buf, state_len, &st) &&
             blind_read_signer_pub(pub_buf, pub_len, root, pk_seed) &&
             xmss_read_sig(sig_buf, sig_len, &sig);
    free(state_buf);
    free(pub_buf);
    free(sig_buf);
    if (!ok)
    {
        fprintf(stderr, "error: malformed user_state.bin, signer_pub.bin or xmss_sig.bin\n");
        blind_user_state_free(&st);
        return 1;
    }

    uint8_t d[32];
    hm_digest(st.com, d);
    if (!xmss_verify(pk_seed, root, d, sizeof d, &sig))
    {
        fprintf(stderr, "error: xmss_sig.bin is not a signature on this commitment "
                        "under signer_pub.bin\n");
        blind_user_state_free(&st);
        return 1;
    }

    printf("prove  ·  KKW N=%d M=%d tau=%d W=%d\n", N_PARTIES, M_KKW, NUM_ROUNDS, GRIND_W);
    fflush(stdout);

    FILE *out = fopen(out_path, "wb");
    if (!out)
    {
        fprintf(stderr, "error: cannot open %s: %s\n", out_path, strerror(errno));
        blind_user_state_free(&st);
        return 1;
    }
    kkw_verbose = 0;
    double t0 = now_ms();
    int rc = blind_user_prove(&st, pk_seed, root, &sig, out);
    double prove_ms = now_ms() - t0;
    long proof_bytes = ftell(out);
    int closed = fclose(out);
    blind_user_state_free(&st);

    if (rc != 0 || closed != 0 || proof_bytes < 0)
    {
        fprintf(stderr, "error: proof generation failed\n");
        return 1;
    }
    printf("  → blind_sig.bin (%.2f MB)  %.0f ms\n", proof_bytes / 1e6, prove_ms);
    return 0;
}

static int cmd_verify(const char *msg_file)
{
    char pub_path[1024], sig_path[1024];
    path_of(pub_path, sizeof pub_path, "signer_pub.bin");
    path_of(sig_path, sizeof sig_path, "blind_sig.bin");

    size_t msg_len = 0, pub_len = 0;
    uint8_t *msg = read_file(msg_file, &msg_len);
    if (!msg)
        return 1;
    uint8_t *pub_buf = read_file(pub_path, &pub_len);
    xmss_node root;
    uint8_t pk_seed[XMSS_PK_SEED_BYTES];
    int ok = pub_buf && blind_read_signer_pub(pub_buf, pub_len, root, pk_seed);
    free(pub_buf);
    if (!ok)
    {
        fprintf(stderr, "error: malformed signer_pub.bin\n");
        free(msg);
        return 1;
    }

    FILE *proof = fopen(sig_path, "rb");
    if (!proof)
    {
        fprintf(stderr, "error: cannot open %s: %s\n", sig_path, strerror(errno));
        free(msg);
        return 1;
    }
    if (fseek(proof, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "error: cannot size %s\n", sig_path);
        fclose(proof);
        free(msg);
        return 1;
    }
    long proof_bytes = ftell(proof);
    rewind(proof);

    printf("verify  ·  KKW N=%d M=%d tau=%d W=%d\n", N_PARTIES, M_KKW, NUM_ROUNDS, GRIND_W);
    fflush(stdout);

    double t0 = now_ms();
    int valid = blind_verify_sig(proof, msg, msg_len, pk_seed, root);
    double verify_ms = now_ms() - t0;
    fclose(proof);
    free(msg);

    printf("  [%s]  %.2f MB  %.0f ms\n", valid ? "PASS" : "FAIL", proof_bytes / 1e6, verify_ms);
    return valid ? 0 : 1;
}

int main(int argc, char **argv)
{
    ASSERT_LIB_PARAMS();
    if (argc < 2)
    {
        usage();
        return 1;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help"))
    {
        usage();
        return 0;
    }

    const char *msg_file = NULL;
    int height = XMSS_H_DEFAULT;
    for (int i = 2; i < argc; i++)
    {
        if (!strcmp(argv[i], "--height"))
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "error: --height needs a value\n");
                return 1;
            }
            height = atoi(argv[++i]);
            if (height < 1 || height > XMSS_H)
            {
                fprintf(stderr, "error: --height must be in 1..%d\n", XMSS_H);
                return 1;
            }
            continue;
        }
        if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dir"))
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "error: --dir needs a value\n");
                return 1;
            }
            g_dir = argv[++i];
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            usage();
            return 0;
        }
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "error: unknown option: %s\n", argv[i]);
            return 1;
        }
        else if (!msg_file)
        {
            msg_file = argv[i];
        }
        else
        {
            fprintf(stderr, "error: too many positional arguments\n");
            return 1;
        }
    }

    const int needs_msg = !strcmp(cmd, "commit") || !strcmp(cmd, "verify");
    if (needs_msg && !msg_file)
    {
        fprintf(stderr, "error: %s needs a <msg_file>\n", cmd);
        return 1;
    }
    if (!needs_msg && msg_file)
    {
        fprintf(stderr, "error: %s takes no positional arguments\n", cmd);
        return 1;
    }

    if (!strcmp(cmd, "keygen"))
        return cmd_keygen(height);
    if (!strcmp(cmd, "commit"))
        return cmd_commit(msg_file);
    if (!strcmp(cmd, "sign"))
        return cmd_sign();
    if (!strcmp(cmd, "prove"))
        return cmd_prove();
    if (!strcmp(cmd, "verify"))
        return cmd_verify(msg_file);

    fprintf(stderr, "error: unknown command: %s\n\n", cmd);
    usage();
    return 1;
}
