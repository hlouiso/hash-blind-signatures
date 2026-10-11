#pragma once
#include "circuit.hpp"

namespace voleith {
inline constexpr size_t kFinalKeccakBits = kProofDegree == 64 ? 27264 : 0;
inline constexpr size_t kWitnessBits =
    43256 + 141 * 1600 * kKeccakSnapshots + kFinalKeccakBits;
inline constexpr size_t kConstraints =
    12801 + 141 * 1600 * kKeccakSnapshots + kFinalKeccakBits;
inline constexpr size_t kPermutations = 141;

// Wire version fixes the circuit, field, degree, tau, domains and tree choices.
inline constexpr std::array<uint8_t, 8> kProofVersion{'H', 'B', 'V', 'I',
                                                      'T', 'H', '0', '3'};

struct ProofLayout {
  size_t nonce, commitment, vole_check, correction, quicksilver, opening, delta,
      counter, size;
};

ProofLayout proof_layout();
Bytes prove(const Statement& statement, const Bytes& primary);
bool verify(const Statement& statement, std::span<const uint8_t> proof);
}
