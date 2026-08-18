#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "circuit/blind_stmt.h"
#include "circuit_cache.h"
#include "commitment.h"
#include "field.h"
#include "protocol.h"
#include "rng.h"
#include "util/log.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {

constexpr size_t kBenchXmssH = 10;
namespace {

using Clock = std::chrono::steady_clock;

double s_since(Clock::time_point t0) {
  return std::chrono::duration<double>(Clock::now() - t0).count();
}

constexpr size_t kMsgBytes = 10 * 1024;

void print_size(const char* label, size_t bytes) {
  if (bytes < 1024) {
    std::printf("    %-38s %10zu B\n", label, bytes);
  } else {
    std::printf("    %-38s %9.2f KB\n", label, bytes / 1024.0);
  }
}

int run(int iters) {
  proofs::set_log_level(proofs::ERROR);
  const Field F;

  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);
  auto t0 = Clock::now();
  auto circuit = build_or_load_circuit(F, pow_x, default_circuit_cache_path());
  const double circuit_s = s_since(t0);

  Bytes message(kMsgBytes);
  DeterministicRng mrng(0xDA7A);
  mrng.fill_bytes(message.data(), message.size());

  double commit_s = 0, sign_s = 0, prove_s = 0, verify_s = 0;
  size_t pk_bytes = 0, sk_bytes = 0, com_bytes = 0, sig_bytes = 0, proof_bytes = 0;
  bool all_ok = true;

  for (int it = 0; it < iters && all_ok; ++it) {

    SignerKey key;
    DeterministicRng krng(0xB0A7 + it);
    krng.fill_bytes(key.sk_seed, kSkSeedBytes);
    krng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
    key.height = static_cast<uint8_t>(kBenchXmssH);
    key.next_leaf = 0;
    const Node xmss_root =
        XmssKeyPair::generate_from_seed(key.sk_seed, key.pk_seed, kBenchXmssH)
            .public_key();

    DeterministicRng urng(0x1000 + it);
    UserState state;
    t0 = Clock::now();
    const HmCommitment com = user_commit(F, urng, message, state);
    commit_s += s_since(t0);

    t0 = Clock::now();
    const auto xmss_sig = signer_sign(key, com);
    sign_s += s_since(t0);
    if (!xmss_sig.has_value()) { all_ok = false; break; }

    t0 = Clock::now();
    const BlindSignature bsig = user_prove(F, *circuit, state, *xmss_sig);
    prove_s += s_since(t0);
    if (bsig.proof.empty()) { all_ok = false; break; }

    t0 = Clock::now();
    all_ok &= verify_blind_sig(F, *circuit, xmss_root, key.pk_seed, bsig,
                               message);
    verify_s += s_since(t0);

    pk_bytes = write_signer_pub(xmss_root, key.pk_seed).size();
    sk_bytes = write_signer_key(key).size();
    com_bytes = write_commitment(com).size();
    sig_bytes = write_xmss_sig(*xmss_sig).size();
    proof_bytes = write_blind_sig(bsig).size();
  }

  const double n = iters;
  commit_s /= n; sign_s /= n; prove_s /= n; verify_s /= n;

  std::printf("blind-xmss-longfellow benchmark  ·  %d iteration%s  ·  %s\n",
              iters, iters == 1 ? "" : "s",
              all_ok ? "all verified" : "*** FAILED ***");
  std::printf("  message %zu B  ·  SHA-256, GF(2^128)  ·  XMSS h=%zu  ·  "
              "WOTS+ l=%zu w=%zu target=%llu\n",
              message.size(), kBenchXmssH, kLen, kW,
              (unsigned long long)xmss_wots_spec().target_sum);
  std::printf("  one-time setup: circuit %.2f s (shared by prover and verifier,"
              " excluded below)\n\n",
              circuit_s);

  std::printf("  Average execution times (s)\n");
  std::printf("    %-38s %10.4f\n", "Commitment computation (user)", commit_s);
  std::printf("    %-38s %10.4f\n", "Key generation + signature (signer)",
              sign_s);
  std::printf("    %-38s %10.4f\n", "Proof generation (user)", prove_s);
  std::printf("    %-38s %10.4f\n\n", "Proof verification (verifier)", verify_s);

  std::printf("  Sizes of the main objects\n");
  print_size("Public key of S (pk)", pk_bytes);
  print_size("Secret key of S (sk)", sk_bytes);
  print_size("Commitment M", com_bytes);
  print_size("Signature of S", sig_bytes);
  print_size("Final signature (NIZK proof)", proof_bytes);

  if (!all_ok) {
    std::fprintf(stderr, "\nbench: the protocol did not complete\n");
    return 1;
  }
  return 0;
}

}
}

int main(int argc, char** argv) {
  int iters = 10;
  if (argc > 1) {
    iters = std::atoi(argv[1]);
    if (iters < 1) iters = 1;
  }
  return blind_longfellow::run(iters);
}
