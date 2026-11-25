/* Native SLH-DSA-SHA2 (FIPS 205 Algorithms 1-24, Section 11.2.1) at security
 * category 1, generic over SlhParams. A port of binius64/src/slh/native.rs.
 *
 * The tweakable hashes F, H, T_l and PRF resume SHA-256 from the midstate of
 * the block PK.seed || 0^48. Signing runs the tree computations on threads;
 * the top XMSS tree is cached in the key, as SP 800-230 Section 3 permits. */

#ifndef BLIND_LONGFELLOW_SLH_NATIVE_H_
#define BLIND_LONGFELLOW_SLH_NATIVE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "slh/params.h"

namespace blind_longfellow {
namespace slh {

using Node = std::array<uint8_t, kN>;
using State = std::array<uint32_t, 8>;
using ByteVec = std::vector<uint8_t>;

constexpr State kSha256Iv = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                             0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                             0x1f83d9abu, 0x5be0cd19u};

enum : uint32_t {
  kWotsHash = 0,
  kWotsPk = 1,
  kTree = 2,
  kForsTree = 3,
  kForsRoots = 4,
  kWotsPrf = 5,
  kForsPrf = 6,
};

// One SHA-256 compression of a 64-byte block into st.
void sha256_compress(State& st, const uint8_t block[64]);
// The state after compressing one block from the IV.
State sha256_block_midstate(const uint8_t block[64]);
// The state after PK.seed || 0^(64 - n).
State pk_seed_midstate(const Node& pk_seed);
// Threads the signer uses: SLH_THREADS, else the hardware concurrency.
size_t signer_threads();

// The 32-byte address of FIPS 205 Section 4.2.
struct Adrs {
  std::array<uint8_t, 32> b{};
  void put(size_t at, uint32_t v);
  uint32_t get(size_t at) const;
  void set_layer(uint32_t l) { put(0, l); }
  void set_tree(uint64_t t);
  void set_type_and_clear(uint32_t ty);
  void set_keypair(uint32_t kp) { put(20, kp); }
  uint32_t keypair() const { return get(20); }
  void set_chain(uint32_t c) { put(24, c); }
  void set_tree_height(uint32_t z) { put(24, z); }
  void set_hash(uint32_t x) { put(28, x); }
  void set_tree_index(uint32_t i) { put(28, i); }
  // ADRSc of FIPS 205 Section 11.2.
  std::array<uint8_t, 22> compressed() const;
};

struct XmssSig {
  std::vector<Node> wots, auth;
};
struct ForsTreeSig {
  Node sk;
  std::vector<Node> auth;
};
struct SlhSignature {
  Node r;
  std::vector<ForsTreeSig> fors;
  std::vector<XmssSig> ht;
  // The FIPS 205 encoding R || SIG_FORS || SIG_HT.
  ByteVec to_bytes() const;
  static std::optional<SlhSignature> from_bytes(const SlhParams& p,
                                                const uint8_t* b, size_t n);
};

// Hash calls one verification makes: tweakable hashes plus the one H_msg.
struct VerifyStats {
  uint64_t f = 0, h = 0, t = 0;
  uint64_t hash_calls() const { return f + h + t + 1; }
};

struct DigestParts {
  ByteVec md;
  uint64_t idx_tree;
  uint32_t idx_leaf;
};

ByteVec h_msg(const Node& r, const Node& pk_seed, const Node& pk_root,
              const uint8_t* msg, size_t len, size_t m);
Node prf_msg(const Node& sk_prf, const Node& opt_rand, const uint8_t* msg,
             size_t len);
// Algorithm 4.
std::vector<uint32_t> base_2b(const uint8_t* x, size_t b, size_t out_len);
// M' of Algorithms 22 and 24 for the pure variant with an empty context.
ByteVec pure_message(const uint8_t* msg, size_t len);

// Public operations, keyed by the public seed.
class SlhCtx {
 public:
  SlhCtx(const SlhParams& p, const Node& pk_seed);

  Node thash(const Adrs& adrs, const uint8_t* data, size_t len) const;
  Node f(const Adrs& adrs, const Node& m) const;
  Node h(const Adrs& adrs, const Node& l, const Node& r) const;
  Node t(const Adrs& adrs, const std::vector<Node>& nodes) const;
  Node prf(const Adrs& adrs, const Node& sk_seed) const;

  // The len base-w digits of Algorithms 7 and 8: message, then checksum.
  std::vector<uint32_t> wots_digits(const Node& msg) const;
  Node wots_sk(const Node& sk_seed, const Adrs& adrs, uint32_t i) const;
  Node wots_pkgen(const Node& sk_seed, const Adrs& adrs) const;
  std::vector<Node> wots_sign(const Node& msg, const Node& sk_seed,
                              const Adrs& adrs) const;
  Node wots_pk_from_sig(const std::vector<Node>& sig, const Node& msg,
                        const Adrs& adrs, VerifyStats& st) const;

  // Every level of one XMSS tree: levels[0] the leaves, levels[hp] the root.
  std::vector<std::vector<Node>> xmss_levels(const Node& sk_seed,
                                             uint32_t layer,
                                             uint64_t tree) const;
  // Levels first..hp of one XMSS tree; levels below `first` stay empty.
  std::vector<std::vector<Node>> xmss_levels_from(const Node& sk_seed,
                                                  uint32_t layer, uint64_t tree,
                                                  uint32_t first) const;
  // The node at height z and index i of one XMSS tree (Algorithm 9).
  Node xmss_node(const Node& sk_seed, uint32_t i, uint32_t z, uint32_t layer,
                 uint64_t tree) const;
  // Algorithm 10; authentication siblings on empty levels are recomputed.
  XmssSig xmss_sign(const Node& msg, const Node& sk_seed, uint32_t idx,
                    uint32_t layer, uint64_t tree,
                    const std::vector<std::vector<Node>>& levels) const;
  Node xmss_pk_from_sig(uint32_t idx, const XmssSig& sig, const Node& msg,
                        uint32_t layer, uint64_t tree, VerifyStats& st) const;

  Node fors_sk(const Node& sk_seed, const Adrs& adrs, uint32_t idx) const;
  Node fors_node(const Node& sk_seed, uint32_t i, uint32_t z,
                 const Adrs& adrs) const;
  std::vector<ForsTreeSig> fors_sign(const uint8_t* md, const Node& sk_seed,
                                     const Adrs& adrs) const;
  Node fors_pk_from_sig(const std::vector<ForsTreeSig>& sig, const uint8_t* md,
                        const Adrs& adrs, VerifyStats& st) const;

  DigestParts split_digest(const ByteVec& digest) const;
  static Adrs fors_adrs(uint64_t idx_tree, uint32_t idx_leaf);

  // Algorithm 20, also counting the hash calls.
  bool verify_internal(const Node& pk_root, const uint8_t* msg, size_t len,
                       const SlhSignature& sig, VerifyStats* st = nullptr) const;

  const SlhParams p;
  const Node pk_seed;
  const State mid;
};

class SlhKey {
 public:
  // Algorithm 18.
  static SlhKey keygen_internal(const SlhParams& p, const Node& sk_seed,
                                const Node& sk_prf, const Node& pk_seed);
  // Algorithm 19; addrnd = nullptr is the deterministic variant.
  SlhSignature sign_internal(const uint8_t* msg, size_t len,
                             const Node* addrnd) const;
  // Pure SLH-DSA with an empty context (Algorithm 22, lines 8-9).
  SlhSignature sign(const uint8_t* msg, size_t len, const Node* addrnd) const;

  // Rebuilds a key from its seeds and the stored levels first..h' of its
  // top-layer tree, without key generation; nullopt unless the levels form
  // that tree's upper part, rooted at pk_root.
  static std::optional<SlhKey> from_top_cache(
      const SlhParams& p, const Node& sk_seed, const Node& sk_prf,
      const Node& pk_seed, const Node& pk_root, size_t first,
      std::vector<std::vector<Node>> levels);
  // The lowest stored height of the top-layer tree.
  size_t top_first() const;

  SlhCtx ctx;
  Node sk_seed, sk_prf, pk_root;
  // The top-layer tree (layer d - 1, tree 0) from height top_first() up.
  // At h' = 22 that is heights 6..22, 2 MiB; a signature recomputes the 63
  // WOTS+ leaves below the cache on its path.
  std::vector<std::vector<Node>> top_levels;
};

// Pure SLH-DSA verification with an empty context (Algorithm 24).
bool slh_verify(const SlhParams& p, const Node& pk_seed, const Node& pk_root,
                const uint8_t* msg, size_t len, const SlhSignature& sig);

}  // namespace slh
}  // namespace blind_longfellow

#endif
