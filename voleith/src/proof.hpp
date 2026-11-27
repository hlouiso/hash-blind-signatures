#pragma once
#include "circuit.hpp"

namespace voleith {
// Degree 64 exposes the last six Keccak rounds directly. Multi-block
// hashes keep the whole state between absorptions and only the digest at
// their end. Degrees 16 and 32 finish at a full-state snapshot instead.
inline constexpr size_t kPermutations = 109 + XMSS_H;
inline constexpr size_t kFinalKeccakBits = kProofDegree == 64
    ? 6 * 1600 + 2 * 256 + (1 + 99 + 1 + XMSS_H) * 128
    : 0;
inline constexpr size_t kKeccakBits =
    kPermutations * 1600 * kKeccakSnapshots + kFinalKeccakBits;
// Each path node supplies a sibling and the selected left child as bits,
// with one packed field constraint to enforce the ordering.
inline constexpr size_t kWitnessBits = 32000 + 256 * XMSS_H + kKeccakBits;
inline constexpr size_t kConstraints = 5642 + XMSS_H + kKeccakBits;

// Wire version fixes the circuit, field, degree, tau, domains and tree choices.
inline constexpr std::array<uint8_t, 8> kProofVersion{'H', 'B', 'V', 'I',
                                                      'T', 'H', '0', '6'};

struct ProofLayout {
  size_t nonce, commitment, vole_check, correction, quicksilver, opening, delta,
      counter, size;
};

ProofLayout proof_layout();
Bytes prove(const Statement& statement, const Bytes& primary);
bool verify(const Statement& statement, std::span<const uint8_t> proof);
}
