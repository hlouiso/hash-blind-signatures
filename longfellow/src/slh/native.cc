#include "slh/native.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <openssl/sha.h>

#include "sha.h"
#include "util/panic.h"

namespace blind_longfellow {
namespace slh {
namespace {

// Each worker evaluates up to 2^14 FORS leaves per job at 128-24.
constexpr uint32_t kForsJobHeight = 14;

template <class Fn>
void parallel_for(size_t n, const Fn& fn) {
  const size_t threads = std::min(signer_threads(), n);
  if (threads <= 1) {
    for (size_t i = 0; i < n; ++i) fn(i);
    return;
  }
  // Claim adjacent items together on large levels, keeping siblings local.
  const size_t chunk = std::clamp(n / threads / 16, size_t{1}, size_t{32});
  std::atomic<size_t> next{0};
  auto worker = [&] {
    for (size_t first; (first = next.fetch_add(chunk, std::memory_order_relaxed)) < n;)
      for (size_t i = first; i < std::min(first + chunk, n); ++i) fn(i);
  };
  std::vector<std::thread> pool;
  pool.reserve(threads - 1);
  for (size_t t = 1; t < threads; ++t) pool.emplace_back(worker);
  worker();
  for (auto& th : pool) th.join();
}

void put_be32(uint8_t* p, uint32_t v) {
  for (size_t i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (24 - 8 * i));
}

Node state_to_node(const State& st) {
  Node out;
  for (size_t i = 0; i < kN / 4; ++i) put_be32(out.data() + 4 * i, st[i]);
  return out;
}

// After the seed midstate, F, H and PRF each need exactly one padded block.
template <size_t Len>
Node short_thash(const State& mid, const Adrs& adrs, const uint8_t* data) {
  constexpr size_t body = 22 + Len;
  static_assert(body <= 55);
  constexpr unsigned bits = (64 + body) * 8;
  uint8_t block[64] = {};
  const auto address = adrs.compressed();
  std::memcpy(block, address.data(), address.size());
  std::memcpy(block + address.size(), data, Len);
  block[body] = 0x80;
  block[62] = bits >> 8;
  block[63] = static_cast<uint8_t>(bits);
  State st = mid;
  sha256_compress(st, block);
  return state_to_node(st);
}

uint64_t to_int(const uint8_t* x, size_t n) {
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i) v = (v << 8) | x[i];
  return v;
}

uint64_t low_bits(uint64_t x, size_t bits) {
  return bits >= 64 ? x : x & ((uint64_t{1} << bits) - 1);
}

Adrs xmss_adrs(uint32_t layer, uint64_t tree) {
  Adrs a;
  a.set_layer(layer);
  a.set_tree(tree);
  return a;
}

}  // namespace

void sha256_compress(State& st, const uint8_t block[64]) {
  // The raw compression function. Deprecated in OpenSSL 3 but still exported,
  // and it uses the ARMv8 / SHA-NI instructions where available.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  SHA256_CTX c;
  std::memcpy(c.h, st.data(), sizeof(c.h));
  SHA256_Transform(&c, block);
  std::memcpy(st.data(), c.h, sizeof(c.h));
#pragma GCC diagnostic pop
#pragma clang diagnostic pop
}

State sha256_block_midstate(const uint8_t block[64]) {
  State st = kSha256Iv;
  sha256_compress(st, block);
  return st;
}

State pk_seed_midstate(const Node& pk_seed) {
  uint8_t block[64] = {};
  std::memcpy(block, pk_seed.data(), kN);
  return sha256_block_midstate(block);
}

size_t signer_threads() {
  static const size_t n = [] {
    if (const char* s = std::getenv("SLH_THREADS")) {
      const long v = std::strtol(s, nullptr, 10);
      if (v > 0) return static_cast<size_t>(v);
    }
    const unsigned hw = std::thread::hardware_concurrency();
    return static_cast<size_t>(hw ? hw : 1);
  }();
  return n;
}

void Adrs::put(size_t at, uint32_t v) { put_be32(b.data() + at, v); }

uint32_t Adrs::get(size_t at) const {
  return static_cast<uint32_t>(to_int(b.data() + at, 4));
}

void Adrs::set_tree(uint64_t t) {
  std::memset(b.data() + 4, 0, 4);
  for (size_t i = 0; i < 8; ++i)
    b[8 + i] = static_cast<uint8_t>(t >> (56 - 8 * i));
}

void Adrs::set_type_and_clear(uint32_t ty) {
  put(16, ty);
  std::memset(b.data() + 20, 0, 12);
}

std::array<uint8_t, 22> Adrs::compressed() const {
  std::array<uint8_t, 22> c;
  c[0] = b[3];
  std::memcpy(c.data() + 1, b.data() + 8, 8);
  c[9] = b[19];
  std::memcpy(c.data() + 10, b.data() + 20, 12);
  return c;
}

ByteVec SlhSignature::to_bytes() const {
  ByteVec out;
  auto put = [&](const Node& n) { out.insert(out.end(), n.begin(), n.end()); };
  put(r);
  for (const auto& t : fors) {
    put(t.sk);
    for (const auto& n : t.auth) put(n);
  }
  for (const auto& x : ht) {
    for (const auto& n : x.wots) put(n);
    for (const auto& n : x.auth) put(n);
  }
  return out;
}

std::optional<SlhSignature> SlhSignature::from_bytes(const SlhParams& p,
                                                     const uint8_t* b,
                                                     size_t n) {
  if (n != p.sig_bytes()) return std::nullopt;
  size_t o = 0;
  auto node = [&] {
    Node x;
    std::memcpy(x.data(), b + o, kN);
    o += kN;
    return x;
  };
  auto nodes = [&](size_t c) {
    std::vector<Node> v(c);
    for (auto& x : v) x = node();
    return v;
  };
  SlhSignature s;
  s.r = node();
  s.fors.resize(p.k);
  for (auto& t : s.fors) {
    t.sk = node();
    t.auth = nodes(p.a);
  }
  s.ht.resize(p.d);
  for (auto& x : s.ht) {
    x.wots = nodes(p.len());
    x.auth = nodes(p.hp);
  }
  return s;
}

ByteVec h_msg(const Node& r, const Node& pk_seed, const Node& pk_root,
              const uint8_t* msg, size_t len, size_t m) {
  ByteVec in(r.begin(), r.end());
  in.insert(in.end(), pk_seed.begin(), pk_seed.end());
  in.insert(in.end(), pk_root.begin(), pk_root.end());
  in.insert(in.end(), msg, msg + len);
  const Hash inner = sha256(in.data(), in.size());
  // MGF1-SHA-256(R || PK.seed || inner, m), RFC 8017 Appendix B.2.1.
  ByteVec seed(r.begin(), r.end());
  seed.insert(seed.end(), pk_seed.begin(), pk_seed.end());
  seed.insert(seed.end(), inner.begin(), inner.end());
  ByteVec out;
  for (uint32_t c = 0; out.size() < m; ++c) {
    ByteVec blk = seed;
    for (size_t i = 0; i < 4; ++i) blk.push_back(static_cast<uint8_t>(c >> (24 - 8 * i)));
    const Hash hc = sha256(blk.data(), blk.size());
    out.insert(out.end(), hc.begin(), hc.end());
  }
  out.resize(m);
  return out;
}

Node prf_msg(const Node& sk_prf, const Node& opt_rand, const uint8_t* msg,
             size_t len) {
  ByteVec in(opt_rand.begin(), opt_rand.end());
  in.insert(in.end(), msg, msg + len);
  const Hash mac = hmac_sha256(sk_prf.data(), kN, in.data(), in.size());
  Node out;
  std::memcpy(out.data(), mac.data(), kN);
  return out;
}

std::vector<uint32_t> base_2b(const uint8_t* x, size_t b, size_t out_len) {
  std::vector<uint32_t> out(out_len);
  size_t in = 0, bits = 0;
  uint64_t total = 0;
  for (size_t o = 0; o < out_len; ++o) {
    while (bits < b) {
      total = (total << 8) | x[in++];
      bits += 8;
    }
    bits -= b;
    out[o] = static_cast<uint32_t>((total >> bits) & ((uint64_t{1} << b) - 1));
  }
  return out;
}

ByteVec pure_message(const uint8_t* msg, size_t len) {
  ByteVec out{0, 0};
  out.insert(out.end(), msg, msg + len);
  return out;
}

SlhCtx::SlhCtx(const SlhParams& p_, const Node& pk_seed_)
    : p(p_), pk_seed(pk_seed_), mid(pk_seed_midstate(pk_seed_)) {
  proofs::check(p.consistent(), "inconsistent SLH-DSA parameters");
}

Node SlhCtx::thash(const Adrs& adrs, const uint8_t* data, size_t len) const {
  // Trunc_n(SHA-256(PK.seed || 0^(64-n) || ADRSc || data)), from the midstate.
  const size_t body = 22 + len;
  const size_t nblocks = (body + 9 + 63) / 64;
  uint8_t stack[128];
  ByteVec heap;
  uint8_t* buf = stack;
  if (nblocks * 64 > sizeof(stack)) {
    heap.resize(nblocks * 64);
    buf = heap.data();
  }
  std::memset(buf, 0, nblocks * 64);
  const auto c = adrs.compressed();
  std::memcpy(buf, c.data(), 22);
  if (len) std::memcpy(buf + 22, data, len);
  buf[body] = 0x80;
  const uint64_t bits = static_cast<uint64_t>(64 + body) * 8;
  for (size_t i = 0; i < 8; ++i)
    buf[nblocks * 64 - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
  State st = mid;
  for (size_t i = 0; i < nblocks; ++i) sha256_compress(st, buf + 64 * i);
  return state_to_node(st);
}

Node SlhCtx::f(const Adrs& adrs, const Node& m) const {
  return short_thash<kN>(mid, adrs, m.data());
}

Node SlhCtx::h(const Adrs& adrs, const Node& l, const Node& r) const {
  uint8_t buf[2 * kN];
  std::memcpy(buf, l.data(), kN);
  std::memcpy(buf + kN, r.data(), kN);
  return short_thash<2 * kN>(mid, adrs, buf);
}

Node SlhCtx::t(const Adrs& adrs, const std::vector<Node>& nodes) const {
  static_assert(sizeof(Node) == kN);
  return thash(adrs, reinterpret_cast<const uint8_t*>(nodes.data()), nodes.size() * kN);
}

Node SlhCtx::prf(const Adrs& adrs, const Node& sk_seed) const {
  return f(adrs, sk_seed);
}

std::vector<uint32_t> SlhCtx::wots_digits(const Node& msg) const {
  const uint32_t w = static_cast<uint32_t>(p.w());
  auto d = base_2b(msg.data(), p.lg_w, p.len1());
  uint64_t csum = 0;
  for (uint32_t x : d) csum += w - 1 - x;
  csum <<= p.csum_shift();
  uint8_t cb[8];
  for (size_t i = 0; i < 8; ++i) cb[i] = static_cast<uint8_t>(csum >> (56 - 8 * i));
  const auto tail = base_2b(cb + 8 - p.csum_bytes(), p.lg_w, p.len2());
  d.insert(d.end(), tail.begin(), tail.end());
  return d;
}

Node SlhCtx::wots_sk(const Node& sk_seed, const Adrs& adrs, uint32_t i) const {
  Adrs a = adrs;
  a.set_type_and_clear(kWotsPrf);
  a.set_keypair(adrs.keypair());
  a.set_chain(i);
  return prf(a, sk_seed);
}

Node SlhCtx::wots_pkgen(const Node& sk_seed, const Adrs& adrs) const {
  const uint32_t w = static_cast<uint32_t>(p.w());
  std::vector<Node> tmp(p.len());
  for (uint32_t i = 0; i < tmp.size(); ++i) {
    Node x = wots_sk(sk_seed, adrs, i);
    Adrs a = adrs;
    a.set_chain(i);
    for (uint32_t j = 0; j < w - 1; ++j) {
      a.set_hash(j);
      x = f(a, x);
    }
    tmp[i] = x;
  }
  Adrs pk = adrs;
  pk.set_type_and_clear(kWotsPk);
  pk.set_keypair(adrs.keypair());
  return t(pk, tmp);
}

std::vector<Node> SlhCtx::wots_sign(const Node& msg, const Node& sk_seed,
                                    const Adrs& adrs) const {
  const auto digits = wots_digits(msg);
  std::vector<Node> sig(digits.size());
  for (uint32_t i = 0; i < digits.size(); ++i) {
    Node x = wots_sk(sk_seed, adrs, i);
    Adrs a = adrs;
    a.set_chain(i);
    for (uint32_t j = 0; j < digits[i]; ++j) {
      a.set_hash(j);
      x = f(a, x);
    }
    sig[i] = x;
  }
  return sig;
}

Node SlhCtx::wots_pk_from_sig(const std::vector<Node>& sig, const Node& msg,
                              const Adrs& adrs, VerifyStats& st) const {
  const uint32_t w = static_cast<uint32_t>(p.w());
  const auto digits = wots_digits(msg);
  std::vector<Node> tmp(p.len());
  for (uint32_t i = 0; i < tmp.size(); ++i) {
    Node x = sig[i];
    Adrs a = adrs;
    a.set_chain(i);
    for (uint32_t j = digits[i]; j < w - 1; ++j) {
      a.set_hash(j);
      x = f(a, x);
      ++st.f;
    }
    tmp[i] = x;
  }
  Adrs pk = adrs;
  pk.set_type_and_clear(kWotsPk);
  pk.set_keypair(adrs.keypair());
  ++st.t;
  return t(pk, tmp);
}

std::vector<std::vector<Node>> SlhCtx::xmss_levels(const Node& sk_seed,
                                                   uint32_t layer,
                                                   uint64_t tree) const {
  return xmss_levels_from(sk_seed, layer, tree, 0);
}

Node SlhCtx::xmss_node(const Node& sk_seed, uint32_t i, uint32_t z,
                       uint32_t layer, uint64_t tree) const {
  const Adrs base = xmss_adrs(layer, tree);
  std::vector<Node> nodes(size_t{1} << z);
  for (size_t j = 0; j < nodes.size(); ++j) {
    Adrs a = base;
    a.set_type_and_clear(kWotsHash);
    a.set_keypair(static_cast<uint32_t>((uint64_t{i} << z) + j));
    nodes[j] = wots_pkgen(sk_seed, a);
  }
  for (uint32_t k = 1; k <= z; ++k) {
    const size_t n = nodes.size() / 2;
    for (size_t j = 0; j < n; ++j) {
      Adrs a = base;
      a.set_type_and_clear(kTree);
      a.set_tree_height(k);
      a.set_tree_index(static_cast<uint32_t>((uint64_t{i} << (z - k)) + j));
      nodes[j] = h(a, nodes[2 * j], nodes[2 * j + 1]);
    }
    nodes.resize(n);
  }
  return nodes[0];
}

std::vector<std::vector<Node>> SlhCtx::xmss_levels_from(const Node& sk_seed,
                                                        uint32_t layer,
                                                        uint64_t tree,
                                                        uint32_t first) const {
  const Adrs base = xmss_adrs(layer, tree);
  std::vector<std::vector<Node>> levels(p.hp + 1);
  levels[first].resize(size_t{1} << (p.hp - first));
  if (first == 0) {
    parallel_for(levels[0].size(), [&](size_t i) {
      Adrs a = base;
      a.set_type_and_clear(kWotsHash);
      a.set_keypair(static_cast<uint32_t>(i));
      levels[0][i] = wots_pkgen(sk_seed, a);
    });
  } else {
    parallel_for(levels[first].size(), [&](size_t i) {
      levels[first][i] =
          xmss_node(sk_seed, static_cast<uint32_t>(i), first, layer, tree);
    });
  }
  for (uint32_t z = first + 1; z <= p.hp; ++z) {
    const auto& prev = levels[z - 1];
    auto& next = levels[z];
    next.resize(prev.size() / 2);
    auto one = [&](size_t i) {
      Adrs a = base;
      a.set_type_and_clear(kTree);
      a.set_tree_height(z);
      a.set_tree_index(static_cast<uint32_t>(i));
      next[i] = h(a, prev[2 * i], prev[2 * i + 1]);
    };
    if (next.size() >= 4096) {
      parallel_for(next.size(), one);
    } else {
      for (size_t i = 0; i < next.size(); ++i) one(i);
    }
  }
  return levels;
}

XmssSig SlhCtx::xmss_sign(const Node& msg, const Node& sk_seed, uint32_t idx,
                          uint32_t layer, uint64_t tree,
                          const std::vector<std::vector<Node>>& levels) const {
  XmssSig s;
  for (size_t j = 0; j < p.hp; ++j) {
    const uint32_t sibling = (idx >> j) ^ 1;
    s.auth.push_back(levels[j].empty()
                         ? xmss_node(sk_seed, sibling, static_cast<uint32_t>(j), layer, tree)
                         : levels[j][sibling]);
  }
  Adrs a = xmss_adrs(layer, tree);
  a.set_type_and_clear(kWotsHash);
  a.set_keypair(idx);
  s.wots = wots_sign(msg, sk_seed, a);
  return s;
}

Node SlhCtx::xmss_pk_from_sig(uint32_t idx, const XmssSig& sig,
                              const Node& msg, uint32_t layer, uint64_t tree,
                              VerifyStats& st) const {
  Adrs a = xmss_adrs(layer, tree);
  a.set_type_and_clear(kWotsHash);
  a.set_keypair(idx);
  Node node = wots_pk_from_sig(sig.wots, msg, a, st);
  a.set_type_and_clear(kTree);
  for (uint32_t k = 0; k < p.hp; ++k) {
    a.set_tree_height(k + 1);
    a.set_tree_index(idx >> (k + 1));
    node = ((idx >> k) & 1) == 0 ? h(a, node, sig.auth[k]) : h(a, sig.auth[k], node);
    ++st.h;
  }
  return node;
}

Node SlhCtx::fors_sk(const Node& sk_seed, const Adrs& adrs,
                     uint32_t idx) const {
  Adrs a = adrs;
  a.set_type_and_clear(kForsPrf);
  a.set_keypair(adrs.keypair());
  a.set_tree_index(idx);
  return prf(a, sk_seed);
}

Node SlhCtx::fors_node(const Node& sk_seed, uint32_t i, uint32_t z,
                       const Adrs& adrs) const {
  Adrs a = adrs;
  if (z == 0) {
    const Node sk = fors_sk(sk_seed, adrs, i);
    a.set_tree_height(0);
    a.set_tree_index(i);
    return f(a, sk);
  }
  const Node l = fors_node(sk_seed, 2 * i, z - 1, adrs);
  const Node r = fors_node(sk_seed, 2 * i + 1, z - 1, adrs);
  a.set_tree_height(z);
  a.set_tree_index(i);
  return h(a, l, r);
}

std::vector<ForsTreeSig> SlhCtx::fors_sign(const uint8_t* md,
                                           const Node& sk_seed,
                                           const Adrs& adrs) const {
  const uint32_t a = static_cast<uint32_t>(p.a);
  const auto idx = base_2b(md, p.a, p.k);
  std::vector<ForsTreeSig> out(p.k);
  // Schedule all authentication subtrees as one batch. A worker owns each
  // output slot. Once they join, reduce the roots at their real FORS addresses.
  struct Subtree {
    uint32_t index, height, job_height;
    std::vector<Node> roots;
  };
  std::vector<Subtree> subtrees;
  subtrees.reserve(p.k * a);
  struct Job { size_t subtree, slot; };
  std::vector<Job> jobs;
  for (uint32_t i = 0; i < p.k; ++i) {
    out[i].sk = fors_sk(sk_seed, adrs, (i << a) + idx[i]);
    out[i].auth.resize(a);
    for (uint32_t j = 0; j < a; ++j) {
      const uint32_t index = (i << (a - j)) + ((idx[i] >> j) ^ 1);
      const uint32_t split = j > kForsJobHeight ? std::min(j - kForsJobHeight, 8u) : 0;
      const size_t count = size_t{1} << split;
      for (size_t k = 0; k < count; ++k) jobs.push_back({subtrees.size(), k});
      subtrees.push_back({index, j, j - split, std::vector<Node>(count)});
    }
  }
  parallel_for(jobs.size(), [&](size_t k) {
    const auto [subtree, slot] = jobs[k];
    auto& t = subtrees[subtree];
    const uint32_t base = t.index << (t.height - t.job_height);
    t.roots[slot] = fors_node(sk_seed, base + static_cast<uint32_t>(slot), t.job_height, adrs);
  });
  for (size_t k = 0; k < subtrees.size(); ++k) {
    auto& t = subtrees[k];
    Adrs ad = adrs;
    for (uint32_t z = t.job_height + 1; z <= t.height; ++z) {
      ad.set_tree_height(z);
      for (size_t j = 0; j < t.roots.size() / 2; ++j) {
        ad.set_tree_index((t.index << (t.height - z)) + static_cast<uint32_t>(j));
        t.roots[j] = h(ad, t.roots[2 * j], t.roots[2 * j + 1]);
      }
      t.roots.resize(t.roots.size() / 2);
    }
    out[k / a].auth[k % a] = t.roots[0];
  }
  return out;
}

Node SlhCtx::fors_pk_from_sig(const std::vector<ForsTreeSig>& sig,
                              const uint8_t* md, const Adrs& adrs,
                              VerifyStats& st) const {
  const uint32_t a = static_cast<uint32_t>(p.a);
  const auto indices = base_2b(md, p.a, p.k);
  Adrs ad = adrs;
  std::vector<Node> roots(p.k);
  for (uint32_t i = 0; i < p.k; ++i) {
    const uint32_t idx = indices[i];
    const uint32_t leaf = (i << a) + idx;
    ad.set_tree_height(0);
    ad.set_tree_index(leaf);
    Node node = f(ad, sig[i].sk);
    ++st.f;
    for (uint32_t j = 0; j < a; ++j) {
      ad.set_tree_height(j + 1);
      ad.set_tree_index(leaf >> (j + 1));
      node = ((idx >> j) & 1) == 0 ? h(ad, node, sig[i].auth[j])
                                   : h(ad, sig[i].auth[j], node);
      ++st.h;
    }
    roots[i] = node;
  }
  Adrs pk = adrs;
  pk.set_type_and_clear(kForsRoots);
  pk.set_keypair(adrs.keypair());
  ++st.t;
  return t(pk, roots);
}

DigestParts SlhCtx::split_digest(const ByteVec& digest) const {
  DigestParts out;
  out.md.assign(digest.begin(), digest.begin() + p.md_bytes());
  const uint8_t* tree_b = digest.data() + p.md_bytes();
  const uint8_t* leaf_b = tree_b + p.tree_bytes();
  out.idx_tree = low_bits(to_int(tree_b, p.tree_bytes()), p.tree_bits());
  out.idx_leaf = static_cast<uint32_t>(low_bits(to_int(leaf_b, p.leaf_bytes()), p.hp));
  return out;
}

Adrs SlhCtx::fors_adrs(uint64_t idx_tree, uint32_t idx_leaf) {
  Adrs a;
  a.set_tree(idx_tree);
  a.set_type_and_clear(kForsTree);
  a.set_keypair(idx_leaf);
  return a;
}

bool SlhCtx::verify_internal(const Node& pk_root, const uint8_t* msg,
                             size_t len, const SlhSignature& sig,
                             VerifyStats* stats) const {
  VerifyStats local;
  VerifyStats& st = stats ? *stats : local;
  if (sig.fors.size() != p.k || sig.ht.size() != p.d) return false;
  for (const auto& t : sig.fors)
    if (t.auth.size() != p.a) return false;
  for (const auto& x : sig.ht)
    if (x.wots.size() != p.len() || x.auth.size() != p.hp) return false;
  const ByteVec digest = h_msg(sig.r, pk_seed, pk_root, msg, len, p.m);
  DigestParts dp = split_digest(digest);
  const Adrs adrs = fors_adrs(dp.idx_tree, dp.idx_leaf);
  Node node = fors_pk_from_sig(sig.fors, dp.md.data(), adrs, st);
  uint64_t tree = dp.idx_tree;
  uint32_t leaf = dp.idx_leaf;
  for (uint32_t j = 0; j < p.d; ++j) {
    if (j > 0) {
      leaf = static_cast<uint32_t>(low_bits(tree, p.hp));
      tree = p.hp >= 64 ? 0 : tree >> p.hp;
    }
    node = xmss_pk_from_sig(leaf, sig.ht[j], node, j, tree, st);
  }
  return node == pk_root;
}

SlhKey SlhKey::keygen_internal(const SlhParams& p, const Node& sk_seed,
                               const Node& sk_prf, const Node& pk_seed) {
  SlhKey key{SlhCtx(p, pk_seed), sk_seed, sk_prf, {}, {}};
  // Keep short trees whole; at h' = 22, heights 6..22.
  const uint32_t first = static_cast<uint32_t>(std::min<size_t>(p.hp > 16 ? p.hp - 16 : 0, 6));
  key.top_levels =
      key.ctx.xmss_levels_from(sk_seed, static_cast<uint32_t>(p.d - 1), 0, first);
  key.pk_root = key.top_levels[p.hp][0];
  return key;
}

size_t SlhKey::top_first() const {
  size_t first = 0;
  while (first < top_levels.size() && top_levels[first].empty()) ++first;
  return first;
}

std::optional<SlhKey> SlhKey::from_top_cache(const SlhParams& p, const Node& sk_seed,
                                             const Node& sk_prf, const Node& pk_seed,
                                             const Node& pk_root, size_t first,
                                             std::vector<std::vector<Node>> levels) {
  if (first > p.hp || levels.size() != p.hp - first + 1) return std::nullopt;
  for (size_t k = 0; k < levels.size(); ++k)
    if (levels[k].size() != size_t{1} << (p.hp - first - k)) return std::nullopt;
  if (levels.back()[0] != pk_root) return std::nullopt;

  SlhKey key{SlhCtx(p, pk_seed), sk_seed, sk_prf, pk_root, {}};
  const Adrs base = xmss_adrs(static_cast<uint32_t>(p.d - 1), 0);
  for (size_t k = 1; k < levels.size(); ++k) {
    const auto& prev = levels[k - 1];
    std::atomic<bool> ok{true};
    parallel_for(levels[k].size(), [&](size_t i) {
      Adrs a = base;
      a.set_type_and_clear(kTree);
      a.set_tree_height(static_cast<uint32_t>(first + k));
      a.set_tree_index(static_cast<uint32_t>(i));
      if (key.ctx.h(a, prev[2 * i], prev[2 * i + 1]) != levels[k][i])
        ok.store(false, std::memory_order_relaxed);
    });
    if (!ok) return std::nullopt;
  }
  key.top_levels.resize(first);
  for (auto& level : levels) key.top_levels.push_back(std::move(level));
  return key;
}

SlhSignature SlhKey::sign_internal(const uint8_t* msg, size_t len,
                                   const Node* addrnd) const {
  const SlhParams& p = ctx.p;
  const Node& opt_rand = addrnd ? *addrnd : ctx.pk_seed;
  SlhSignature sig;
  sig.r = prf_msg(sk_prf, opt_rand, msg, len);
  const ByteVec digest = h_msg(sig.r, ctx.pk_seed, pk_root, msg, len, p.m);
  const DigestParts dp = ctx.split_digest(digest);
  const Adrs adrs = SlhCtx::fors_adrs(dp.idx_tree, dp.idx_leaf);
  sig.fors = ctx.fors_sign(dp.md.data(), sk_seed, adrs);
  VerifyStats ignored;
  Node node = ctx.fors_pk_from_sig(sig.fors, dp.md.data(), adrs, ignored);
  // Algorithm 12, reusing the cached top tree.
  uint64_t tree = dp.idx_tree;
  uint32_t leaf = dp.idx_leaf;
  for (uint32_t j = 0; j < p.d; ++j) {
    if (j > 0) {
      leaf = static_cast<uint32_t>(low_bits(tree, p.hp));
      tree = p.hp >= 64 ? 0 : tree >> p.hp;
    }
    std::vector<std::vector<Node>> computed;
    const std::vector<std::vector<Node>>* levels = &top_levels;
    if (j + 1 != p.d) {
      computed = ctx.xmss_levels(sk_seed, j, tree);
      levels = &computed;
    }
    sig.ht.push_back(ctx.xmss_sign(node, sk_seed, leaf, j, tree, *levels));
    node = (*levels)[p.hp][0];
  }
  return sig;
}

SlhSignature SlhKey::sign(const uint8_t* msg, size_t len,
                          const Node* addrnd) const {
  const ByteVec mp = pure_message(msg, len);
  return sign_internal(mp.data(), mp.size(), addrnd);
}

bool slh_verify(const SlhParams& p, const Node& pk_seed, const Node& pk_root,
                const uint8_t* msg, size_t len, const SlhSignature& sig) {
  const ByteVec mp = pure_message(msg, len);
  return SlhCtx(p, pk_seed).verify_internal(pk_root, mp.data(), mp.size(), sig);
}

}  // namespace slh
}  // namespace blind_longfellow
