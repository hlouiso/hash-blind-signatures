// Benchmarks of the blind signature on VOLEitH, stateful (XMSS) by default or
// stateless (SLH-DSA-SHAKE-128-24) with --stateless, like blindsig keygen.
//
// Both follow the paper's methodology: a 10,240-byte document; each iteration
// commits, has the signer sign, proves and verifies; proof generation is the
// user's final round with witness generation included and verification is the
// blind-signature verifier, both means over the iterations (default 10). The
// stateless run reports key generation separately; `height` (default 10) is
// the real XMSS tree height of the stateful run.
//
//   ./build/bench [--stateful] [iterations] [height]
//   SLH_THREADS=8 /usr/bin/time -l ./build/bench --stateless [iterations]
#include "protocol.hpp"
#include "slh_protocol.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace voleith;

namespace {
constexpr const char* kUsage =
    "usage: bench [--stateful] [iterations] [height]\n"
    "       bench --stateless [iterations]";

double now() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int argument(const char* text, int maximum) {
  const std::string value(text);
  size_t used = 0;
  int n = 0;
  try {
    n = std::stoi(value, &used);
  } catch (const std::logic_error&) {
    used = 0;
  }
  if (used == 0 || used != value.size() || n < 1 || n > maximum)
    throw std::invalid_argument("benchmark argument out of range: " + value);
  return n;
}

void print_size(const char* label, size_t bytes) {
  if (bytes < 1024)
    std::printf("    %-38s %10zu B\n", label, bytes);
  else
    std::printf("    %-38s %8.2f KiB\n", label, bytes / 1024.0);
}

void run_stateful(int runs, int height) {
  if (uint64_t(runs) > (uint64_t(1) << height))
    throw std::invalid_argument("iterations exceed XMSS key capacity");

  Bytes message(10 * 1024, 0x61);
  SecretKey key;
  PublicKey pk;
  {
    auto signer = Signer::generate(height);
    key = signer.secret_key();
    pk = signer.public_key();
  }

  double commit_s = 0, sign_s = 0, prove_s = 0, verify_s = 0;
  size_t com_bytes = 0, sig_bytes = 0, proof_bytes = 0;
  for (int i = 0; i < runs; ++i) {
    double t = now();
    auto state = commit(message);
    commit_s += now() - t;

    xmss_sig response{};
    t = now();
    {
      Signer signer(key);
      response = signer.sign(state.commitment);
      key = signer.secret_key();
    }
    sign_s += now() - t;

    t = now();
    auto proof = unblind(state, pk, response);
    prove_s += now() - t;

    t = now();
    const bool valid = verify_signature(pk, message, proof);
    verify_s += now() - t;
    if (!valid) throw std::runtime_error("benchmark verification failed");
    com_bytes = encode(state.commitment).size();
    sig_bytes = encode(response).size();
    proof_bytes = proof.size();
  }

  std::printf(
      "blind-xmss-voleith benchmark  ·  %d iteration%s  ·  all verified\n",
      runs, runs == 1 ? "" : "s");
  std::printf(
      "  message %zu B  ·  SHAKE256, GF(2^128)  ·  XMSS h=%d  ·  "
      "WOTS+ l=%d w=%d target=%d\n",
      message.size(), height, XMSS_WOTS_LEN, XMSS_WOTS_W, XMSS_TARGET_SUM);
  std::printf("  VOLE trees=%zu  ·  degree=%zu  ·  grinding=%zu bits\n\n",
              kVoleTrees, kProofDegree, kGrindingBits);

  std::printf("  Average execution times (s)\n");
  std::printf("    %-38s %10.6f\n", "Commitment computation (user)",
              commit_s / runs);
  std::printf("    %-38s %10.6f\n", "Key generation + signature (signer)",
              sign_s / runs);
  std::printf("    %-38s %10.6f\n", "Proof generation (user)", prove_s / runs);
  std::printf("    %-38s %10.6f\n\n", "Proof verification (verifier)",
              verify_s / runs);

  std::printf("  Sizes of the main objects\n");
  print_size("Public key of S (pk)", encode(pk).size());
  print_size("Secret key of S (sk)", encode(key).size());
  print_size("Commitment M", com_bytes);
  print_size("Signature of S", sig_bytes);
  print_size("Final signature (NIZK proof)", proof_bytes);
}

// Stateless: SLH-DSA-SHAKE-128-24 as the underlying signature.
void run_stateless(int runs) {
  const slh_params& p = kSlhShake128_24;
  const SlhDims dims = slh_proof_dims(p);
  std::printf("== %s on VOLEitH  (signature %zu B, %zu signer threads, %d iterations)\n",
              p.name, slh_sig_bytes(&p), slh_threads(), runs);
  std::printf("  VOLE trees=%zu  degree=%zu  grinding=%zu bits\n", kVoleTrees, kProofDegree,
              kGrindingBits);
  std::printf("  circuit: %zu Keccak-f permutations, %zu constraints, %zu-byte extended "
              "witness (%zu primary)\n",
              dims.permutations, dims.constraints, dims.witness_bits / 8, dims.primary_bytes);

  Bytes message(10 * 1024, 0x61);
  double t = now();
  const SlhSigner signer = SlhSigner::generate(p);
  const double keygen_s = now() - t;
  const SlhPublicKey pk = signer.public_key();

  double commit_s = 0, sign_s = 0, prove_s = 0, verify_s = 0;
  size_t proof_bytes = 0;
  for (int i = 0; i < runs; ++i) {
    t = now();
    const SlhUserState state = slh_commit(message);
    commit_s += now() - t;
    t = now();
    const Bytes sig = signer.sign(state.commitment);
    sign_s += now() - t;
    t = now();
    const Bytes proof = slh_unblind(p, state, pk, sig);
    prove_s += now() - t;
    t = now();
    const bool ok = slh_verify_signature(p, pk, message, proof);
    verify_s += now() - t;
    if (!ok) throw std::runtime_error("benchmark verification failed");
    proof_bytes = proof.size();
    if (i == 0) {
      Bytes other = message;
      other[0] ^= 1;
      if (slh_verify_signature(p, pk, other, proof))
        throw std::runtime_error("a wrong document verified");
    }
  }
  std::printf("  signer: keygen %.2f s, sign %.3f s (mean of %d)\n", keygen_s, sign_s / runs,
              runs);
  std::printf("  Commitment (user)          %8.4f s\n", commit_s / runs);
  std::printf("  Proof generation (user)    %8.4f s\n", prove_s / runs);
  std::printf("  Proof verification         %8.4f s\n", verify_s / runs);
  std::printf("  Blind signature            %8.2f KB  (%zu bytes)\n", proof_bytes / 1000.0,
              proof_bytes);
  std::printf("  all verified; a wrong document is rejected\n");
}
}  // namespace

int main(int argc, char** argv) try {
  bool stateless = false;
  std::vector<const char*> positional;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--stateful") == 0)
      stateless = false;
    else if (std::strcmp(argv[i], "--stateless") == 0)
      stateless = true;
    else if (std::strncmp(argv[i], "--", 2) == 0)
      throw std::invalid_argument(std::string("unknown option ") + argv[i] + "\n" + kUsage);
    else
      positional.push_back(argv[i]);
  }
  if (positional.size() > (stateless ? 1u : 2u)) throw std::invalid_argument(kUsage);
  const int runs = positional.empty() ? 10 : argument(positional[0], 1000);
  if (stateless) {
    run_stateless(runs);
  } else {
    const int height = positional.size() > 1 ? argument(positional[1], XMSS_H) : XMSS_H_DEFAULT;
    run_stateful(runs, height);
  }
} catch (const std::exception& e) {
  std::cerr << e.what() << '\n';
  return 1;
}
