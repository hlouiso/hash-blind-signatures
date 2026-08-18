#include "protocol.h"

#include "kkw_prove.h"
#include "randombytes.h"
#include "shared.h"
#include "xmss.h"

#include <errno.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#ifndef BENCH_ITERS
#define BENCH_ITERS 10
#endif
#define BENCH_MSG_LEN 10240

#ifndef BENCH_XMSS_H
#define BENCH_XMSS_H 10
#endif

static void random_or_die(void *buffer, size_t length)
{
    if (!randombytes_fill(buffer, length))
    {
        fprintf(stderr, "OS random generator failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static double average(const double *v, int n)
{
    double s = 0.0;
    for (int i = 0; i < n; i++)
        s += v[i];
    return s / n;
}

static void cpu_model(char *buf, size_t n)
{
#if defined(__APPLE__)

    if (sysctlbyname("machdep.cpu.brand_string", buf, &n, NULL, 0) == 0)
        return;
    snprintf(buf, n, "unknown");
#else
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f)
    {
        snprintf(buf, n, "unknown");
        return;
    }
    char line[256];
    while (fgets(line, sizeof line, f))
    {
        if (strncmp(line, "model name", 10) == 0)
        {
            char *p = strchr(line, ':');
            if (p)
            {
                p += 2;
                p[strcspn(p, "\n")] = '\0';
                snprintf(buf, n, "%s", p);
                fclose(f);
                return;
            }
        }
    }
    fclose(f);
    snprintf(buf, n, "unknown");
#endif
}

typedef struct
{
    double commit_s, sign_s, prove_s, verify_s;
    double proof_bytes;
} bench_result;

static bench_result run_pipeline(int iters, int progress)
{
    double commit[BENCH_ITERS], sign[BENCH_ITERS], prove[BENCH_ITERS], verify[BENCH_ITERS];
    double size[BENCH_ITERS];

    blind_signer_key key;
    xmss_node root;
    if (!blind_keygen(&key, BENCH_XMSS_H, root))
    {
        fprintf(stderr, "\nkey generation failed\n");
        exit(EXIT_FAILURE);
    }

    uint8_t *msg = malloc(BENCH_MSG_LEN);
    if (!msg)
    {
        fprintf(stderr, "\nout of memory\n");
        exit(EXIT_FAILURE);
    }
    random_or_die(msg, BENCH_MSG_LEN);

    kkw_verbose = 0;

    if (progress)
    {
        fprintf(stderr, "  # measuring N=%d (%d iteration%s):", N_PARTIES, iters,
                iters == 1 ? "" : "s");
        fflush(stderr);
    }

    for (int i = 0; i < iters; i++)
    {
        double t0;

        blind_user_state st;
        t0 = now_s();
        int ok = blind_user_commit(msg, BENCH_MSG_LEN, &st);
        commit[i] = now_s() - t0;
        if (!ok)
        {
            fprintf(stderr, "\ncommit failed at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        uint8_t persisted[BLIND_SIGNER_KEY_BYTES];
        blind_write_signer_key(&key, persisted);
        blind_signer_key_free(&key);
        if (!blind_read_signer_key(persisted, sizeof persisted, &key))
        {
            fprintf(stderr, "\nkey round trip failed at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        xmss_sig sig;
        t0 = now_s();
        ok = blind_signer_sign(&key, st.com, &sig);
        sign[i] = now_s() - t0;
        if (!ok)
        {
            fprintf(stderr, "\nsign failed at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        FILE *proof = tmpfile();
        if (!proof)
        {
            fprintf(stderr, "\ntmpfile() failed at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        t0 = now_s();
        int rc = blind_user_prove(&st, key.pk_seed, root, &sig, proof);
        prove[i] = now_s() - t0;
        if (rc != 0)
        {
            fprintf(stderr, "\nprove failed at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        size[i] = (double)ftell(proof);
        rewind(proof);

        t0 = now_s();
        int valid = blind_verify_sig(proof, msg, BENCH_MSG_LEN, key.pk_seed, root);
        verify[i] = now_s() - t0;
        fclose(proof);
        blind_user_state_free(&st);
        if (!valid)
        {
            fprintf(stderr, "\nverification FAILED at iter %d\n", i);
            exit(EXIT_FAILURE);
        }

        if (progress && ((i + 1) % 5 == 0 || i + 1 == iters))
        {
            fprintf(stderr, " %d/%d", i + 1, iters);
            fflush(stderr);
        }
    }
    if (progress)
        fprintf(stderr, "\n");
    free(msg);
    blind_signer_key_free(&key);

    bench_result out;
    out.commit_s = average(commit, iters);
    out.sign_s = average(sign, iters);
    out.prove_s = average(prove, iters);
    out.verify_s = average(verify, iters);
    out.proof_bytes = average(size, iters);
    return out;
}

static void print_size(const char *label, double bytes)
{
    if (bytes < 1024.0)
        printf("    %-38s %10.0f B\n", label, bytes);
    else if (bytes < 1024.0 * 1024.0)
        printf("    %-38s %9.2f KB\n", label, bytes / 1024.0);
    else
        printf("    %-38s %9.2f MB\n", label, bytes / (1024.0 * 1024.0));
}

int main(int argc, char *argv[])
{
    ASSERT_LIB_PARAMS();
    const int iters = BENCH_ITERS;
    const int header_only = (argc > 1 && strcmp(argv[1], "--header") == 0);
    const int row_only = (argc > 1 && strcmp(argv[1], "--row") == 0);

    char cpu[128];
    cpu_model(cpu, sizeof cpu);

    if (header_only)
    {
        printf("blind-mss-kkw benchmark  ·  %s  ·  %d threads  ·  %d iteration%s\n",
               cpu, omp_get_max_threads(), iters, iters == 1 ? "" : "s");
        printf("  message %d B  ·  BLAKE3 tweakable hash, GF(2^128)  ·  XMSS h=%d  ·  "
               "WOTS+ l=%d w=%d target=%d  ·  W=%d grinding bits\n\n",
               BENCH_MSG_LEN, BENCH_XMSS_H, XMSS_WOTS_LEN, XMSS_WOTS_W, XMSS_TARGET_SUM, GRIND_W);
        printf("  Blind signature as the number of MPC parties N grows\n");
        printf("    %5s %5s %5s %14s %14s %16s\n", "N", "M", "tau", "Proof size", "Proving (s)",
               "Verification (s)");
        return 0;
    }

    const bench_result r = run_pipeline(iters,  1);

    if (row_only)
    {
        printf("    %5d %5d %5d %11.2f MB %14.3f %16.3f\n", N_PARTIES, M_KKW, NUM_ROUNDS,
               r.proof_bytes / (1024.0 * 1024.0), r.prove_s, r.verify_s);
        return 0;
    }

    printf("\n  Average execution times (s), N=%d\n", N_PARTIES);
    printf("    %-38s %10.4f\n", "Commitment computation (user)", r.commit_s);
    printf("    %-38s %10.4f\n", "Key generation + signature (signer)", r.sign_s);
    printf("    %-38s %10.4f\n", "Proof generation (user)", r.prove_s);
    printf("    %-38s %10.4f\n\n", "Proof verification (verifier)", r.verify_s);

    printf("  Sizes of the main objects, N=%d\n", N_PARTIES);
    print_size("Public key of S (pk)", BLIND_SIGNER_PUB_BYTES);
    print_size("Secret key of S (sk)", BLIND_SIGNER_KEY_BYTES);
    print_size("Commitment M", HM_COM_BYTES);
    print_size("Signature of S", XMSS_SIG_BYTES);
    print_size("Final signature (NIZK proof)", r.proof_bytes);
    return 0;
}
