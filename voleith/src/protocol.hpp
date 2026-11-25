#pragma once
#include "proof.hpp"
#include <functional>
#include <memory>

namespace voleith {
struct PublicKey {
  std::array<uint8_t, 16> seed, root;
  uint8_t height;
};

struct UserState {
  std::array<uint8_t, 32> digest;
  std::array<uint8_t, 96> r;
  std::array<uint8_t, 256> commitment;
};

using Commitment = std::array<uint8_t, 256>;

struct SecretKey {
  std::array<uint8_t, 32> seed;
  std::array<uint8_t, 16> public_seed;
  uint8_t height = XMSS_H_DEFAULT;
  uint64_t next_leaf = 0;
};

class Signer {
  SecretKey key_;
  std::unique_ptr<xmss_keypair, decltype(&xmss_keypair_free)> tree_;
  Signer(SecretKey key, xmss_keypair* tree);

 public:
  explicit Signer(SecretKey key);
  // Splits the tree at `subtree_h`, so that top_cache() holds the levels above.
  Signer(SecretKey key, int subtree_h);
  static Signer generate(int height = XMSS_H_DEFAULT);
  // Like generate, split at xmss_cache_split_height for a stored top cache.
  static Signer generate_cached(int height = XMSS_H_DEFAULT);
  // Resumes a signer from top_cache() without sweeping the leaves; nullopt
  // unless the nodes fit (key.height, subtree_h) and form one tree.
  static std::optional<Signer> from_cache(SecretKey key, int subtree_h,
                                          std::span<const uint8_t> nodes);
  // The levels above the split, from the bottom one up, and the split.
  Bytes top_cache() const;
  int subtree_height() const;
  PublicKey public_key() const;

  const SecretKey& secret_key() const { return key_; }

  // Persist is called after reserving the leaf and before producing a response.
  // A failed operation consumes its leaf. CLI callers hold the state-file lock.
  xmss_sig sign(const Commitment& com,
                const std::function<void(const SecretKey&)>& persist = {});
};

std::array<uint8_t, 32> message_digest(std::span<const uint8_t> message);
UserState commit(std::span<const uint8_t> message);
Bytes primary_witness(const UserState& state, const PublicKey& pk,
                      const xmss_sig& response);
Bytes unblind(const UserState& state, const PublicKey& pk,
              const xmss_sig& response);
bool verify_signature(const PublicKey& pk, std::span<const uint8_t> message,
                      std::span<const uint8_t> signature);

Bytes encode(const PublicKey& pk);
Bytes encode(const SecretKey& sk);
Bytes encode(const UserState& state);
Bytes encode(const Commitment& com);
Bytes encode(const xmss_sig& response);
PublicKey decode_public(std::span<const uint8_t> data);
SecretKey decode_secret(std::span<const uint8_t> data);
UserState decode_state(std::span<const uint8_t> data);
Commitment decode_commitment(std::span<const uint8_t> data);
xmss_sig decode_response(std::span<const uint8_t> data);
}
