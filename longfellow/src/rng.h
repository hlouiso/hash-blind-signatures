#ifndef BLIND_LONGFELLOW_RNG_H_
#define BLIND_LONGFELLOW_RNG_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include <openssl/rand.h>

#include "sha.h"
#include "util/panic.h"

namespace blind_longfellow {

class Rng {
 public:
  virtual ~Rng() = default;
  virtual void fill_bytes(uint8_t* out, size_t n) = 0;
};

class DeterministicRng : public Rng {
 public:
  explicit DeterministicRng(uint64_t seed) {
    static constexpr uint8_t kLabel[] =
        "blind-xmss-longfellow/test-rng/v1";
    Bytes material(kLabel, kLabel + sizeof(kLabel) - 1);
    for (size_t i = 0; i < sizeof(seed); ++i)
      material.push_back(static_cast<uint8_t>(seed >> (8 * i)));
    key_ = sha256(material);
  }

  void fill_bytes(uint8_t* out, size_t n) override {
    size_t written = 0;
    while (written < n) {
      if (block_pos_ == block_.size()) refill();
      const size_t take = std::min(n - written, block_.size() - block_pos_);
      std::memcpy(out + written, block_.data() + block_pos_, take);
      block_pos_ += take;
      written += take;
    }
  }

 private:
  void refill() {
    std::array<uint8_t, sizeof(counter_)> encoded_counter{};
    for (size_t i = 0; i < encoded_counter.size(); ++i)
      encoded_counter[i] = static_cast<uint8_t>(counter_ >> (8 * i));
    block_ = hmac_sha256(key_.data(), key_.size(), encoded_counter.data(),
                         encoded_counter.size());
    ++counter_;
    block_pos_ = 0;
  }

  Hash key_{};
  uint64_t counter_ = 0;
  Hash block_{};
  size_t block_pos_ = kHashBytes;
};

class SecureRng : public Rng {
 public:
  void fill_bytes(uint8_t* out, size_t n) override {
    constexpr size_t kMaxRandRequest =
        static_cast<size_t>(std::numeric_limits<int>::max());
    while (n != 0) {
      const size_t chunk = std::min(n, kMaxRandRequest);
      proofs::check(RAND_bytes(out, static_cast<int>(chunk)) == 1,
                    "RAND_bytes failed");
      out += chunk;
      n -= chunk;
    }
  }
};

}

#endif
