#include "protocol.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace voleith;

namespace {
double now() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int argument(const char* text, int maximum) {
  size_t used = 0;
  const std::string value(text);
  const int n = std::stoi(value, &used);
  if (used != value.size() || n < 1 || n > maximum)
    throw std::invalid_argument("benchmark argument out of range");
  return n;
}

void print_size(const char* label, size_t bytes) {
  if (bytes < 1024)
    std::printf("    %-38s %10zu B\n", label, bytes);
  else
    std::printf("    %-38s %9.2f KB\n", label, bytes / 1024.0);
}
}

int main(int argc, char** argv) try {
  if (argc > 3)
    throw std::invalid_argument("usage: bench [iterations] [height]");
  const int runs = argc > 1 ? argument(argv[1], 1000) : 10;
  const int height = argc > 2 ? argument(argv[2], XMSS_H) : XMSS_H_DEFAULT;
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
} catch (const std::exception& e) {
  std::cerr << e.what() << '\n';
  return 1;
}
