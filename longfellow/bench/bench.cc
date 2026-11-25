/* Benchmarks of the blind signature on Longfellow, stateful (XMSS) by
 * default or stateless (SLH-DSA-SHA2-128-24) with --stateless, like
 * blindsig keygen.
 *
 * Both follow the paper's methodology: a 10,240-byte document; proof
 * generation is the user's final round with witness generation included;
 * verification is the blind-signature verifier; both are means over the
 * iterations (default 10). Circuit compilation is excluded. The stateless
 * run reports key generation and the signer's round separately; its first
 * run compiles the SLH-DSA circuit into the build directory (about a minute
 * and 16 GB of memory, once).
 *
 *   ./build/bench [--stateful | --stateless] [iterations]
 *   SLH_THREADS=8 /usr/bin/time -l ./build/bench --stateless [iterations] */

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "circuit/blind_stmt.h"
#include "circuit/slh_stmt.h"
#include "circuit_cache.h"
#include "commitment.h"
#include "field.h"
#include "protocol.h"
#include "rng.h"
#include "slh/commit.h"
#include "slh/native.h"
#include "slh/params.h"
#include "slh/prover.h"
#include "slh/protocol.h"
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
    std::printf("    %-38s %8.2f KiB\n", label, bytes / 1024.0);
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
    const SignerPub pub{
        XmssKeyPair::generate_from_seed(key.sk_seed, key.pk_seed, kBenchXmssH)
            .public_key(),
        key.pk_seed, key.height};

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
    all_ok &= verify_blind_sig(F, *circuit, pub, bsig, message);
    verify_s += s_since(t0);

    pk_bytes = write_signer_pub(pub).size();
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

// Stateless: SLH-DSA-SHA2-128-24 as the underlying signature.
namespace slh {
namespace {

int run(const SlhParams& p, int iters) {
  proofs::set_log_level(proofs::ERROR);
  const Field F;
  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);

  std::printf("== %s on Longfellow  (signature %zu B, %zu signer threads, %d iterations)\n",
              p.name, p.sig_bytes(), signer_threads(), iters);

  DeterministicRng krng(0x5148B);
  Node sk_seed, sk_prf, pk_seed;
  krng.fill_bytes(sk_seed.data(), kN);
  krng.fill_bytes(sk_prf.data(), kN);
  krng.fill_bytes(pk_seed.data(), kN);
  auto t0 = Clock::now();
  const SlhKey key = SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed);
  const double keygen_s = s_since(t0);
  const SlhPublicKey pk{pk_seed, key.pk_root};

  t0 = Clock::now();
  bool hit = false;
  const auto circuit = build_or_load_slh_circuit(
      F, p, pow_x, slh_circuit_cache_path(p, SLH_CIRCUIT_CACHE_DIR), &hit);
  const double circuit_s = s_since(t0);
  size_t wires = 0;
  for (const auto& layer : circuit->l) wires += layer.nw;
  const LigeroLayout lig = slh_ligero_layout(*circuit);

  Bytes doc(kMsgBytes);
  DeterministicRng mrng(0xDA7A);
  mrng.fill_bytes(doc.data(), doc.size());

  double commit_s = 0, sign_s = 0, prove_s = 0, verify_s = 0;
  std::vector<size_t> sizes;
  bool ok = true;
  for (int it = 0; it < iters && ok; ++it) {
    DeterministicRng urng(0x1000 + it);
    SlhUserState state;
    t0 = Clock::now();
    const HmCommitment com = slh_user_commit(F, urng, doc, state);
    commit_s += s_since(t0);

    t0 = Clock::now();
    const SlhSignature sig = slh_signer_sign(key, com, urng);
    sign_s += s_since(t0);

    t0 = Clock::now();
    const auto proof = slh_user_prove(F, p, *circuit, state, pk, sig);
    prove_s += s_since(t0);
    ok &= !proof.empty();

    t0 = Clock::now();
    ok &= slh_verify_blind(F, p, *circuit, pk, proof, doc);
    verify_s += s_since(t0);
    sizes.push_back(proof.size());
  }
  if (ok) {
    // A wrong document must not verify.
    DeterministicRng urng(0x2000);
    SlhUserState state;
    const HmCommitment com = slh_user_commit(F, urng, doc, state);
    const auto proof =
        slh_user_prove(F, p, *circuit, state, pk, slh_signer_sign(key, com, urng));
    Bytes other = doc;
    other[0] ^= 1;
    ok &= !slh_verify_blind(F, p, *circuit, pk, proof, other);
  }

  const double n = static_cast<double>(sizes.size());
  double mean = 0;
  for (size_t s : sizes) mean += static_cast<double>(s);
  mean /= n;
  const auto mm = std::minmax_element(sizes.begin(), sizes.end());

  std::printf("  circuit: %zu SHA-256 compressions, %zu inputs (%zu public), "
              "%zu layers, %zu wires, %zu terms\n",
              SlhShape(p).total(), circuit->ninputs, circuit->npub_in, circuit->nl,
              wires, circuit->nterms());
  std::printf("  Ligero: rate 1/%zu, nreq %zu, witnesses %zu, block %zu, "
              "block_enc %zu, dblock %zu, rows %zu\n",
              lig.rateinv, lig.nreq, lig.witnesses, lig.block, lig.block_enc,
              lig.dblock, lig.nrow);
  std::printf("  circuit %s in %.2f s (excluded)\n", hit ? "loaded from cache" : "compiled",
              circuit_s);
  std::printf("  signer: keygen %.2f s, sign %.3f s (mean of %d)\n", keygen_s,
              sign_s / n, static_cast<int>(n));
  std::printf("  Commitment (user)          %8.4f s\n", commit_s / n);
  std::printf("  Proof generation (user)    %8.4f s\n", prove_s / n);
  std::printf("  Proof verification         %8.4f s\n", verify_s / n);
  std::printf("  Blind signature            %8.2f KB  (mean of %d; min %zu, max %zu bytes)\n",
              mean / 1000.0, static_cast<int>(n), *mm.first, *mm.second);
  std::printf("  %s\n", ok ? "all verified; a wrong document is rejected"
                           : "*** FAILED ***");
  return ok ? 0 : 1;
}

}  // namespace
}  // namespace slh
}  // namespace blind_longfellow

namespace {

constexpr const char* kUsage = "usage: bench [--stateful | --stateless] [iterations]";

}  // namespace

int main(int argc, char** argv) {
  bool stateless = false;
  int iters = 10;
  bool have_iters = false;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (std::strcmp(arg, "--stateful") == 0) {
      stateless = false;
    } else if (std::strcmp(arg, "--stateless") == 0) {
      stateless = true;
    } else {
      char* end = nullptr;
      const long n = std::strtol(arg, &end, 10);
      if (have_iters || end == arg || *end != '\0') {
        std::fprintf(stderr, "bench: unexpected argument '%s'\n%s\n", arg, kUsage);
        return 2;
      }
      iters = static_cast<int>(std::clamp(n, 1L, 1000000L));
      have_iters = true;
    }
  }
  if (stateless)
    return blind_longfellow::slh::run(blind_longfellow::slh::kSlhSha2_128_24, iters);
  return blind_longfellow::run(iters);
}
