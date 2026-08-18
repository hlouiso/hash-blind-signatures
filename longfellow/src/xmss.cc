#include "xmss.h"

#include <algorithm>

#include <array>
#include <cstring>

#include "rng.h"
#include "util/panic.h"

namespace blind_longfellow {
namespace {

constexpr uint8_t kWotsPrfLabel[] =
    "blind-xmss-longfellow/wots/v1";

constexpr uint8_t kUpperSiblingLabel[] =
    "blind-xmss-longfellow/upper-siblings/v1";

void put_u32le(uint8_t* out, uint32_t v) {
  out[0] = static_cast<uint8_t>(v);
  out[1] = static_cast<uint8_t>(v >> 8);
  out[2] = static_cast<uint8_t>(v >> 16);
  out[3] = static_cast<uint8_t>(v >> 24);
}

Hash derive_wots_prf_key(const uint8_t sk_seed[kSkSeedBytes]) {
  return hmac_sha256(sk_seed, kSkSeedBytes, kWotsPrfLabel,
                     sizeof(kWotsPrfLabel) - 1);
}

Node derive_wots_secret(const Hash& wots_prf_key, const PkSeed& pk_seed,
                        uint32_t leaf, uint32_t chain) {
  std::array<uint8_t, kPkSeedBytes + 4 + 4> address{};
  std::memcpy(address.data(), pk_seed.data(), pk_seed.size());
  put_u32le(address.data() + kPkSeedBytes, leaf);
  put_u32le(address.data() + kPkSeedBytes + 4, chain);

  const Hash output = hmac_sha256(
      wots_prf_key.data(), wots_prf_key.size(), address.data(), address.size());
  Node secret;
  std::memcpy(secret.data(), output.data(), secret.size());
  return secret;
}

std::vector<Node> derive_upper_siblings(const uint8_t sk_seed[kSkSeedBytes],
                                        size_t levels) {
  const Hash key = hmac_sha256(sk_seed, kSkSeedBytes, kUpperSiblingLabel,
                               sizeof(kUpperSiblingLabel) - 1);
  std::vector<Node> upper(levels);
  for (size_t i = 0; i < levels; ++i) {
    std::array<uint8_t, 4> index{};
    put_u32le(index.data(), static_cast<uint32_t>(i));
    const Hash out =
        hmac_sha256(key.data(), key.size(), index.data(), index.size());
    std::memcpy(upper[i].data(), out.data(), kNodeBytes);
  }
  return upper;
}

Node climb_upper(const Bytes& param, const Node& real_root, size_t height,
                 const std::vector<Node>& upper) {
  Node node = real_root;
  for (size_t i = 0; i < upper.size(); ++i) {
    node = hash_tree_node(param, node, upper[i],
                          static_cast<uint32_t>(height + i), 0);
  }
  return node;
}

}

std::pair<Node, std::vector<TreeHashCall>> xmss_auth_path(
    const Bytes& param, const Node& leaf, uint32_t leaf_index,
    const AuthPath& auth_path) {
  std::vector<TreeHashCall> calls;
  calls.reserve(kXmssH);
  Node node = leaf;
  uint32_t idx = leaf_index;

  for (size_t h = 0; h < kXmssH; ++h) {
    const Node& sibling = auth_path[h];
    const bool node_is_left = (idx & 1) == 0;
    const Node& left = node_is_left ? node : sibling;
    const Node& right = node_is_left ? sibling : node;
    const uint32_t node_idx = idx >> 1;
    const Node output = hash_tree_node(param, left, right,
                                       static_cast<uint32_t>(h), node_idx);
    calls.push_back(TreeHashCall{left, right, output, node_is_left,
                                 static_cast<uint32_t>(h), node_idx});
    node = output;
    idx >>= 1;
  }
  return {node, std::move(calls)};
}

bool xmss_verify(const WinternitzSpec& spec, const PkSeed& pk_seed,
                 const Node& expected_root, uint32_t leaf_index,
                 const uint8_t* message, size_t message_len,
                 const Bytes& nonce, const std::vector<Node>& sig_hashes,
                 const AuthPath& auth_path) {
  if (sig_hashes.size() != spec.dimension()) return false;

  const Bytes param = build_wots_domain_param(pk_seed);

  const Hash mh = hash_message(param, leaf_index, nonce.data(), nonce.size(),
                               message, message_len);
  bool leftover_ok = false;
  const std::vector<uint8_t> coords = extract_coords(mh.data(), &leftover_ok);
  if (!leftover_ok) return false;
  uint64_t sum = 0;
  for (uint8_t c : coords) sum += c;
  if (sum != spec.target_sum) return false;

  const std::vector<Node> pk_hashes =
      compute_wots_pk_hashes(param, leaf_index, sig_hashes, coords);
  const Node leaf = hash_public_key(param, leaf_index, pk_hashes);

  const auto [root, calls] = xmss_auth_path(param, leaf, leaf_index, auth_path);
  (void)calls;
  return root == expected_root;
}

std::optional<XmssSignature> xmss_expand(const WinternitzSpec& spec,
                                         const PkSeed& pk_seed,
                                         uint32_t leaf_index,
                                         const Bytes& nonce,
                                         const std::vector<Node>& sig_hashes,
                                         const AuthPath& auth_path,
                                         const uint8_t* message,
                                         size_t message_len) {
  if (sig_hashes.size() != spec.dimension()) return std::nullopt;

  const Bytes param = build_wots_domain_param(pk_seed);

  const Hash mh = hash_message(param, leaf_index, nonce.data(), nonce.size(),
                               message, message_len);
  bool leftover_ok = false;
  std::vector<uint8_t> coords = extract_coords(mh.data(), &leftover_ok);
  if (!leftover_ok) return std::nullopt;
  uint64_t sum = 0;
  for (uint8_t c : coords) sum += c;
  if (sum != spec.target_sum) return std::nullopt;

  std::vector<Node> pk_hashes =
      compute_wots_pk_hashes(param, leaf_index, sig_hashes, coords);
  const Node leaf = hash_public_key(param, leaf_index, pk_hashes);

  auto [root, calls] = xmss_auth_path(param, leaf, leaf_index, auth_path);

  XmssSignature sig;
  sig.wots.domain_param = param;
  sig.wots.epoch = leaf_index;
  sig.wots.nonce = nonce;
  sig.wots.coords = std::move(coords);
  sig.wots.sig_hashes = sig_hashes;
  sig.wots.pk_hashes = std::move(pk_hashes);
  sig.wots.tweaked_message = build_message_hash(
      param, leaf_index, nonce.data(), nonce.size(), message, message_len);
  sig.wots.message_hash = mh;
  sig.leaf = leaf;
  sig.auth_path = auth_path;
  sig.xmss_calls = std::move(calls);
  sig.root = root;
  sig.leaf_index = leaf_index;
  return sig;
}

XmssKeyPair XmssKeyPair::generate(Rng& rng, const PkSeed& pk_seed,
                                  size_t height) {
  std::array<uint8_t, kSkSeedBytes> sk_seed;
  rng.fill_bytes(sk_seed.data(), sk_seed.size());
  return generate_from_seed(sk_seed.data(), pk_seed, height);
}

XmssKeyPair XmssKeyPair::generate_from_seed(const uint8_t sk_seed[kSkSeedBytes],
                                            const PkSeed& pk_seed,
                                            size_t height) {
  return generate_from_seed_split(sk_seed, pk_seed, height,
                                  std::min(height, kSubtreeH));
}

std::vector<Node> XmssKeyPair::wots_secret_key(uint32_t leaf_index) const {
  const Hash wots_prf_key = derive_wots_prf_key(sk_seed_);
  std::vector<Node> sk;
  sk.reserve(kLen);
  for (size_t chain = 0; chain < kLen; ++chain) {
    sk.push_back(derive_wots_secret(wots_prf_key, pk_seed_, leaf_index,
                                    static_cast<uint32_t>(chain)));
  }
  return sk;
}

std::vector<std::vector<Node>> XmssKeyPair::build_subtree(uint32_t s) const {
  const Bytes param = build_wots_domain_param(pk_seed_);
  const size_t width = size_t{1} << subtree_h_;
  const uint64_t base_epoch = uint64_t{s} << subtree_h_;

  std::vector<Node> leaves;
  leaves.reserve(width);
  for (size_t j = 0; j < width; ++j) {
    const uint32_t epoch = static_cast<uint32_t>(base_epoch + j);
    const std::vector<Node> sk = wots_secret_key(epoch);
    const std::vector<Node> pk = compute_wots_public_key(param, epoch, sk);
    leaves.push_back(hash_public_key(param, epoch, pk));
  }

  std::vector<std::vector<Node>> levels;
  levels.push_back(std::move(leaves));
  for (size_t h = 1; h <= subtree_h_; ++h) {
    const std::vector<Node>& prev = levels[h - 1];
    const size_t n = size_t{1} << (subtree_h_ - h);
    const uint64_t base_index = uint64_t{s} << (subtree_h_ - h);
    std::vector<Node> level;
    level.reserve(n);
    for (size_t j = 0; j < n; ++j) {
      level.push_back(hash_tree_node(param, prev[2 * j], prev[2 * j + 1],
                                     static_cast<uint32_t>(h - 1),
                                     static_cast<uint32_t>(base_index + j)));
    }
    levels.push_back(std::move(level));
  }
  return levels;
}

XmssKeyPair XmssKeyPair::generate_from_seed_split(
    const uint8_t sk_seed[kSkSeedBytes], const PkSeed& pk_seed, size_t height,
    size_t subtree_h) {
  proofs::check(height >= 1 && height <= kXmssH, "XMSS height out of range");
  proofs::check(subtree_h >= 1 && subtree_h <= height,
                "XMSS subtree height out of range");

  const Bytes param = build_wots_domain_param(pk_seed);
  const size_t top_h = height - subtree_h;

  XmssKeyPair kp;
  kp.pk_seed_ = pk_seed;
  std::memcpy(kp.sk_seed_, sk_seed, kSkSeedBytes);
  kp.height_ = height;
  kp.subtree_h_ = subtree_h;

  std::vector<Node> subtree_roots;
  subtree_roots.reserve(size_t{1} << top_h);
  for (uint64_t s = 0; s < uint64_t{1} << top_h; ++s) {
    kp.bottom_ = kp.build_subtree(static_cast<uint32_t>(s));
    kp.cached_subtree_ = s;
    subtree_roots.push_back(kp.bottom_[subtree_h][0]);
  }

  kp.top_.push_back(std::move(subtree_roots));
  for (size_t r = 1; r <= top_h; ++r) {
    const std::vector<Node>& prev = kp.top_[r - 1];
    const size_t n = size_t{1} << (top_h - r);
    std::vector<Node> level;
    level.reserve(n);
    for (size_t i = 0; i < n; ++i) {
      level.push_back(hash_tree_node(param, prev[2 * i], prev[2 * i + 1],
                                     static_cast<uint32_t>(subtree_h + r - 1),
                                     static_cast<uint32_t>(i)));
    }
    kp.top_.push_back(std::move(level));
  }

  kp.upper_ = derive_upper_siblings(sk_seed, kXmssH - height);
  kp.root_ = climb_upper(param, kp.top_[top_h][0], height, kp.upper_);
  return kp;
}

AuthPath XmssKeyPair::extract_auth_path(uint32_t leaf_index) {
  const uint64_t s = uint64_t{leaf_index} >> subtree_h_;
  if (cached_subtree_ != s) {
    bottom_ = build_subtree(static_cast<uint32_t>(s));
    cached_subtree_ = s;
  }

  AuthPath path;
  uint64_t idx = leaf_index;
  for (size_t h = 0; h < subtree_h_; ++h) {

    const uint64_t base = s << (subtree_h_ - h);
    path[h] = bottom_[h][(idx ^ 1) - base];
    idx >>= 1;
  }

  for (size_t r = 0; r < height_ - subtree_h_; ++r) {
    path[subtree_h_ + r] = top_[r][idx ^ 1];
    idx >>= 1;
  }

  for (size_t h = height_; h < kXmssH; ++h) path[h] = upper_[h - height_];
  return path;
}

std::optional<XmssSignature> XmssKeyPair::sign(const WinternitzSpec& spec,
                                               Rng& rng,
                                               const uint8_t* message,
                                               size_t message_len) {
  if (next_leaf_ >= capacity()) return std::nullopt;
  const uint32_t leaf_index = static_cast<uint32_t>(next_leaf_);
  ++next_leaf_;

  const Bytes param = build_wots_domain_param(pk_seed_);

  const GrindResult grind =
      grind_nonce(spec, rng, param, leaf_index, message, message_len);

  const std::vector<Node> sig_hashes = compute_wots_signature(
      param, leaf_index, wots_secret_key(leaf_index), grind.coords);
  const std::vector<Node> pk_hashes =
      compute_wots_pk_hashes(param, leaf_index, sig_hashes, grind.coords);
  const Node leaf = hash_public_key(param, leaf_index, pk_hashes);

  const AuthPath auth_path = extract_auth_path(leaf_index);
  auto [root, calls] = xmss_auth_path(param, leaf, leaf_index, auth_path);
  proofs::check(root == root_, "XMSS root mismatch during signing");

  WotsSigningData wots;
  wots.domain_param = param;
  wots.epoch = leaf_index;
  wots.nonce = grind.nonce;
  wots.coords = grind.coords;
  wots.sig_hashes = sig_hashes;
  wots.pk_hashes = pk_hashes;
  wots.tweaked_message = grind.tweaked_message;
  wots.message_hash = hash_message(param, leaf_index, grind.nonce.data(),
                                   grind.nonce.size(), message, message_len);

  XmssSignature sig;
  sig.wots = std::move(wots);
  sig.leaf = leaf;
  sig.auth_path = auth_path;
  sig.xmss_calls = std::move(calls);
  sig.root = root;
  sig.leaf_index = leaf_index;
  return sig;
}

}
