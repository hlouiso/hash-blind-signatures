/* Base-8 target-sum WOTS+ with 42 coordinates summing to 195. Nonce grinding
 * also requires the two unused digest bits to be zero (about 2^14.85 trials).
 * The resulting encoding layer is about 2^113.2, below a 128-bit target. */

#ifndef BLIND_LONGFELLOW_WOTS_H_
#define BLIND_LONGFELLOW_WOTS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rng.h"
#include "sha.h"

namespace blind_longfellow {

constexpr size_t kW = 8;
constexpr size_t kMaxSteps = kW - 1;
constexpr size_t kLen = 42;

constexpr size_t kDigitsPerWord = kLen / 2;

struct WinternitzSpec {
  size_t message_hash_len;
  size_t coordinate_resolution_bits;
  uint64_t target_sum;
  size_t domain_param_len;

  size_t dimension() const { return kLen; }
  size_t chain_len() const { return size_t{1} << coordinate_resolution_bits; }
};

constexpr WinternitzSpec xmss_wots_spec() {
  return WinternitzSpec{ 16,
3,
195,
kPkSeedBytes};
}

static_assert(kLen * 3 + 2 == 16 * 8,
              "the codeword must exhaust the message hash");
static_assert(2 * kDigitsPerWord == kLen,
              "the codeword must split evenly across the two digest words");

constexpr size_t coord_bit_pos(size_t i) {
  return i < kDigitsPerWord ? 3 * i : 64 + 3 * (i - kDigitsPerWord);
}

std::vector<uint8_t> extract_coords(const uint8_t* hash, bool* leftover_ok);

struct GrindResult {
  Bytes tweaked_message;
  std::vector<uint8_t> coords;
  Bytes nonce;
};

GrindResult grind_nonce(const WinternitzSpec& spec, Rng& rng,
                        const Bytes& param, uint32_t epoch,
                        const uint8_t* message, size_t message_len);

std::vector<Node> compute_wots_pk_hashes(const Bytes& param, uint32_t epoch,
                                         const std::vector<Node>& sig_hashes,
                                         const std::vector<uint8_t>& coords);

std::vector<Node> generate_wots_secret_key(Rng& rng);

std::vector<Node> compute_wots_public_key(const Bytes& param, uint32_t epoch,
                                          const std::vector<Node>& sk);

std::vector<Node> compute_wots_signature(const Bytes& param, uint32_t epoch,
                                         const std::vector<Node>& sk,
                                         const std::vector<uint8_t>& coords);

struct WotsSigningData {
  Bytes domain_param;
  uint32_t epoch;
  Bytes nonce;
  std::vector<uint8_t> coords;
  std::vector<Node> sig_hashes;
  std::vector<Node> pk_hashes;
  Bytes tweaked_message;
  Hash message_hash;

  static WotsSigningData generate(const WinternitzSpec& spec, Rng& rng,
                                  Bytes domain_param, uint32_t epoch,
                                  const uint8_t* message, size_t message_len);
};

}

#endif
