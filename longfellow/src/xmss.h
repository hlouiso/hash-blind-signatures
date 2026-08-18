/* Stateful XMSS. The circuit always verifies 32 levels; a key of real height
 * h < 32 uses fixed seed-derived siblings above h. The signer materializes the
 * top tree and caches only the bottom subtree containing the current leaf.
 * next_leaf must be persisted: a WOTS+ leaf must never be reused. */

#ifndef BLIND_LONGFELLOW_XMSS_H_
#define BLIND_LONGFELLOW_XMSS_H_

#include <array>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "rng.h"
#include "sha.h"
#include "wots.h"

namespace blind_longfellow {

constexpr size_t kXmssH = 32;

constexpr size_t kXmssHDefault = 10;

constexpr size_t kSubtreeH = 16;

constexpr size_t kSkSeedBytes = 32;

using AuthPath = std::array<Node, kXmssH>;

struct TreeHashCall {
  Node left;
  Node right;
  Node output;
  bool node_is_left;
  uint32_t height;
  uint32_t node_index;
};

struct XmssSignature {
  WotsSigningData wots;
  Node leaf;
  AuthPath auth_path;
  std::vector<TreeHashCall> xmss_calls;
  Node root;
  uint32_t leaf_index;
};

std::pair<Node, std::vector<TreeHashCall>> xmss_auth_path(
    const Bytes& param, const Node& leaf, uint32_t leaf_index,
    const AuthPath& auth_path);

bool xmss_verify(const WinternitzSpec& spec, const PkSeed& pk_seed,
                 const Node& expected_root, uint32_t leaf_index,
                 const uint8_t* message, size_t message_len,
                 const Bytes& nonce, const std::vector<Node>& sig_hashes,
                 const AuthPath& auth_path);

std::optional<XmssSignature> xmss_expand(const WinternitzSpec& spec,
                                         const PkSeed& pk_seed,
                                         uint32_t leaf_index,
                                         const Bytes& nonce,
                                         const std::vector<Node>& sig_hashes,
                                         const AuthPath& auth_path,
                                         const uint8_t* message,
                                         size_t message_len);

class XmssKeyPair {
 public:
  static XmssKeyPair generate(Rng& rng, const PkSeed& pk_seed,
                              size_t height = kXmssHDefault);

  std::optional<XmssSignature> sign(const WinternitzSpec& spec, Rng& rng,
                                    const uint8_t* message, size_t message_len);

  const Node& public_key() const { return root_; }
  const PkSeed& pk_seed() const { return pk_seed_; }
  size_t height() const { return height_; }
  uint64_t capacity() const { return uint64_t{1} << height_; }
  uint64_t next_leaf() const { return next_leaf_; }
  uint64_t remaining() const { return capacity() - next_leaf_; }
  void set_next_leaf(uint64_t leaf) { next_leaf_ = leaf; }

  static XmssKeyPair generate_from_seed(const uint8_t sk_seed[kSkSeedBytes],
                                        const PkSeed& pk_seed,
                                        size_t height = kXmssHDefault);

  static XmssKeyPair generate_from_seed_split(const uint8_t sk_seed[kSkSeedBytes],
                                              const PkSeed& pk_seed,
                                              size_t height, size_t subtree_h);

  std::vector<Node> wots_secret_key(uint32_t leaf_index) const;

 private:
  AuthPath extract_auth_path(uint32_t leaf_index);

  std::vector<std::vector<Node>> build_subtree(uint32_t s) const;

  PkSeed pk_seed_;
  Node root_;
  uint8_t sk_seed_[kSkSeedBytes]{};
  size_t height_ = kXmssHDefault;
  size_t subtree_h_ = kSubtreeH;

  std::vector<std::vector<Node>> top_;

  std::vector<std::vector<Node>> bottom_;
  uint64_t cached_subtree_ = kNoSubtree;
  std::vector<Node> upper_;
  uint64_t next_leaf_ = 0;

  static constexpr uint64_t kNoSubtree = ~uint64_t{0};
};

}

#endif
