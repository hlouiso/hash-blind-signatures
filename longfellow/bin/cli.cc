#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "circuit/blind_stmt.h"
#include "circuit_cache.h"
#include "field.h"
#include "protocol.h"
#include "rng.h"
#include "slh/commit.h"
#include "slh/protocol.h"
#include "util/log.h"
#include "xmss.h"

namespace blind_longfellow {
namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open: " + path);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open: " + path);
  f.write(reinterpret_cast<const char*>(data.data()),
          static_cast<std::streamsize>(data.size()));
  if (!f) throw std::runtime_error("cannot write: " + path);
}

std::string hex(const uint8_t* p, size_t n) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(2 * n);
  for (size_t i = 0; i < n; ++i) {
    s += kDigits[p[i] >> 4];
    s += kDigits[p[i] & 0xf];
  }
  return s;
}

// The underlying signature scheme, chosen at keygen and recorded in the keys.
enum class Scheme { kStateful, kStateless };

const char* scheme_name(Scheme s) {
  return s == Scheme::kStateful ? "stateful (XMSS)"
                                : "stateless (SLH-DSA-SHA2-128-24)";
}

const slh::SlhParams& kStatelessParams = slh::kSlhSha2_128_24;

struct Options {
  std::string dir = ".";
  std::string cache;
  std::string msg_file;
  std::optional<Scheme> scheme;

  std::string path(const char* name) const { return dir + "/" + name; }
  std::string cache_path() const {
    return cache.empty() ? default_circuit_cache_path() : cache;
  }
  std::string slh_cache_path() const {
    return cache.empty()
               ? slh::slh_circuit_cache_path(kStatelessParams, SLH_CIRCUIT_CACHE_DIR)
               : cache;
  }
};

// The stateful scheme fixes the XMSS height at the kXmssH levels the circuit
// checks; a key file of any other height was not made by this keygen.
void require_fixed_height(size_t height, const char* file) {
  if (height != kXmssH)
    throw std::runtime_error(std::string(file) + " has XMSS height " +
                             std::to_string(height) + "; keys have height " +
                             std::to_string(kXmssH) + ", run keygen again");
}

void usage() {
  std::fprintf(stderr,
      "usage: blindsig <command> [options]\n"
      "\n"
      "commands:\n"
      "  keygen                signer:   generate a key pair\n"
      "  commit <msg_file>     user:     commit to a message (round 1)\n"
      "  sign                  signer:   sign the commitment (round 1 reply)\n"
      "  prove                 user:     build the blind signature (round 2)\n"
      "  verify <msg_file>     verifier: check the blind signature\n"
      "\n"
      "options:\n"
      "  -d, --dir <path>      directory holding the artefacts (default \".\")\n"
      "  --stateful            keygen only, the default: XMSS of height 24\n"
      "                        underneath, 2^24 one-time signatures (the\n"
      "                        lifetime of SLH-DSA-128-24). Each signature\n"
      "                        consumes a leaf, and sign rewrites signer_key.bin.\n"
      "                        keygen sweeps all 2^24 leaves, about a minute.\n"
      "  --stateless           keygen only: SLH-DSA-SHA2-128-24 underneath. sign\n"
      "                        never rewrites signer_key.bin. The other commands\n"
      "                        follow the scheme recorded in the key files.\n"
      "                        In both schemes keygen also writes\n"
      "                        signer_cache.bin, the upper levels of the\n"
      "                        signer's tree, so that sign rebuilds one small\n"
      "                        subtree instead of the whole key; without it,\n"
      "                        sign rebuilds the key and rewrites the cache.\n"
      "  --circuit-cache <p>   circuit cache file for prove/verify (default: the\n"
      "                        build's cache for the key's scheme). The first\n"
      "                        stateless prove or verify compiles its circuit\n"
      "                        once: about a minute and 16 GB of memory.\n"
      "  -h, --help\n");
}

std::unique_ptr<proofs::Circuit<Field>> open_circuit(const Field& F,
                                                     const Options& opt) {
  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);
  const auto t0 = Clock::now();
  bool cache_hit = false;
  auto circuit = build_or_load_circuit(F, pow_x, opt.cache_path(), &cache_hit);
  std::printf("  circuit  : %s  %.0f ms  (%zu layers)\n",
              cache_hit ? "cache hit" : "compiled + cached", ms_since(t0),
              circuit->nl);
  return circuit;
}

bool file_exists(const std::string& path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

std::unique_ptr<proofs::Circuit<Field>> open_slh_circuit(const Field& F,
                                                         const Options& opt) {
  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);
  const std::string path = opt.slh_cache_path();
  if (!file_exists(path))
    std::printf("  circuit  : compiling %s once (about a minute, 16 GB peak)\n",
                kStatelessParams.name);
  const auto t0 = Clock::now();
  bool cache_hit = false;
  auto circuit =
      slh::build_or_load_slh_circuit(F, kStatelessParams, pow_x, path, &cache_hit);
  std::printf("  circuit  : %s  %.0f ms  (%zu layers)\n",
              cache_hit ? "cache hit" : "compiled + cached", ms_since(t0),
              circuit->nl);
  return circuit;
}

// signer_cache.bin: the upper levels of the signer's tree, so that sign
// rebuilds one small subtree rather than the whole key. It is magic ||
// header || levels || tag, the tag HMAC-SHA-256 under sk_seed of everything
// before it, which ties the cache to its key. The XMSS header is
// height || split and holds levels split..height; the SLH-DSA header is
// first and holds levels first..h'. A missing or invalid cache only costs
// time: sign rebuilds the tree and writes a fresh cache.
const std::array<uint8_t, 8> kXmssCacheMagic = {'H', 'B', 'S', '-', 'X', 'M', 'S', 'C'};
const std::array<uint8_t, 8> kSlhCacheMagic = {'H', 'B', 'S', '-', 'S', 'L', 'H', 'C'};
constexpr char kCacheTagLabel[] = "blindsig-longfellow/signer-cache/v1";

Hash cache_tag(const uint8_t* secret, size_t secret_len, const uint8_t* body,
               size_t n) {
  Bytes msg(kCacheTagLabel, kCacheTagLabel + sizeof(kCacheTagLabel) - 1);
  msg.insert(msg.end(), body, body + n);
  return hmac_sha256(secret, secret_len, msg.data(), msg.size());
}

std::vector<uint8_t> write_cache(const std::array<uint8_t, 8>& magic,
                                 const std::vector<uint8_t>& header,
                                 const std::vector<std::vector<Node>>& levels,
                                 size_t first, const uint8_t* secret,
                                 size_t secret_len) {
  std::vector<uint8_t> out(magic.begin(), magic.end());
  out.insert(out.end(), header.begin(), header.end());
  for (size_t z = first; z < levels.size(); ++z)
    for (const Node& n : levels[z]) out.insert(out.end(), n.begin(), n.end());
  const Hash tag = cache_tag(secret, secret_len, out.data(), out.size());
  out.insert(out.end(), tag.begin(), tag.end());
  return out;
}

// Levels first..top of a cache file whose header has `header_len` bytes.
std::optional<std::vector<std::vector<Node>>> read_cache_levels(
    const std::vector<uint8_t>& buf, size_t header_len, size_t first, size_t top,
    const uint8_t* secret, size_t secret_len) {
  size_t count = 0;
  for (size_t z = first; z <= top; ++z) count += size_t{1} << (top - z);
  const size_t body = 8 + header_len + count * kNodeBytes;
  if (buf.size() != body + kHashBytes) return std::nullopt;
  const Hash tag = cache_tag(secret, secret_len, buf.data(), body);
  if (!std::equal(tag.begin(), tag.end(), buf.begin() + body)) return std::nullopt;
  std::vector<std::vector<Node>> levels;
  const uint8_t* q = buf.data() + 8 + header_len;
  for (size_t z = first; z <= top; ++z) {
    std::vector<Node> level(size_t{1} << (top - z));
    for (Node& n : level) {
      std::memcpy(n.data(), q, kNodeBytes);
      q += kNodeBytes;
    }
    levels.push_back(std::move(level));
  }
  return levels;
}

std::optional<std::vector<uint8_t>> read_optional(const std::string& path) {
  if (!file_exists(path)) return std::nullopt;
  return read_file(path);
}

std::optional<XmssKeyPair> load_xmss_cache(const Options& opt, const SignerKey& key) {
  const auto buf = read_optional(opt.path("signer_cache.bin"));
  if (!buf || buf->size() < 10 || !slh::has_magic(*buf, kXmssCacheMagic))
    return std::nullopt;
  const size_t height = (*buf)[8], split = (*buf)[9];
  if (height != key.height || split < 1 || split > height) return std::nullopt;
  auto levels = read_cache_levels(*buf, 2, split, height, key.sk_seed, kSkSeedBytes);
  if (!levels) return std::nullopt;
  return XmssKeyPair::from_top_levels(key.sk_seed, key.pk_seed, height, split,
                                      std::move(*levels));
}

std::vector<uint8_t> xmss_cache_bytes(const XmssKeyPair& kp, const SignerKey& key) {
  std::vector<std::vector<Node>> levels = kp.top_levels();
  return write_cache(kXmssCacheMagic,
                     {key.height, static_cast<uint8_t>(kp.subtree_height())},
                     levels, 0, key.sk_seed, kSkSeedBytes);
}

std::optional<slh::SlhKey> load_slh_cache(const Options& opt, const slh::SlhParams& p,
                                          const slh::SlhSecretKey& sk) {
  const auto buf = read_optional(opt.path("signer_cache.bin"));
  if (!buf || buf->size() < 9 || !slh::has_magic(*buf, kSlhCacheMagic))
    return std::nullopt;
  const size_t first = (*buf)[8];
  if (first > p.hp) return std::nullopt;
  auto levels = read_cache_levels(*buf, 1, first, p.hp, sk.sk_seed.data(), sk.sk_seed.size());
  if (!levels) return std::nullopt;
  return slh::SlhKey::from_top_cache(p, sk.sk_seed, sk.sk_prf, sk.pk_seed, sk.pk_root,
                                     first, std::move(*levels));
}

std::vector<uint8_t> slh_cache_bytes(const slh::SlhKey& key) {
  const size_t first = key.top_first();
  return write_cache(kSlhCacheMagic, {static_cast<uint8_t>(first)}, key.top_levels,
                     first, key.sk_seed.data(), key.sk_seed.size());
}

const char* tree_source(bool from_cache) {
  return from_cache ? "from signer_cache.bin"
                    : "rebuilt (no valid signer_cache.bin), cache written";
}

// signer_pub.bin tells the user and the verifier which scheme the signer has.
Scheme read_pub_scheme(const Options& opt, const char* who,
                       std::vector<uint8_t>& bytes) {
  try {
    bytes = read_file(opt.path("signer_pub.bin"));
  } catch (const std::exception&) {
    throw std::runtime_error(std::string(who) +
                             " needs signer_pub.bin, which records the "
                             "signer's scheme; run keygen first");
  }
  return slh::has_magic(bytes, slh::kSlhPubMagic) ? Scheme::kStateless
                                                  : Scheme::kStateful;
}

std::vector<uint8_t> read_state_file(const Options& opt, Scheme scheme) {
  auto bytes = read_file(opt.path("user_state.bin"));
  const Scheme made_for = slh::has_magic(bytes, slh::kSlhStateMagic)
                              ? Scheme::kStateless
                              : Scheme::kStateful;
  if (made_for != scheme)
    throw std::runtime_error(
        std::string("user_state.bin was committed for the ") +
        scheme_name(made_for) + " scheme but signer_pub.bin is " +
        scheme_name(scheme) + "; run commit again");
  return bytes;
}

int keygen_stateless(const Options& opt) {
  const slh::SlhParams& p = kStatelessParams;
  SecureRng rng;
  slh::Node sk_seed, sk_prf, pk_seed;
  rng.fill_bytes(sk_seed.data(), sk_seed.size());
  rng.fill_bytes(sk_prf.data(), sk_prf.size());
  rng.fill_bytes(pk_seed.data(), pk_seed.size());

  const auto t0 = Clock::now();
  const slh::SlhKey key = slh::SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed);
  const double keygen_ms = ms_since(t0);

  const slh::SlhSecretKey sk{sk_seed, sk_prf, pk_seed, key.pk_root};
  const auto key_bytes = slh::write_slh_key(p, sk);
  const auto pub_bytes = slh::write_slh_pub(p, sk.public_key());
  const auto cache_bytes = slh_cache_bytes(key);
  write_file(opt.path("signer_key.bin"), key_bytes);
  write_file(opt.path("signer_pub.bin"), pub_bytes);
  write_file(opt.path("signer_cache.bin"), cache_bytes);

  std::printf("keygen  ·  stateless  ·  %s (at most 2^24 signatures)  %.0f ms\n",
              p.name, keygen_ms);
  std::printf("  pk_root  : %s\n", hex(key.pk_root.data(), key.pk_root.size()).c_str());
  std::printf("  pk_seed  : %s\n", hex(pk_seed.data(), pk_seed.size()).c_str());
  std::printf("  → signer_key.bin (%zu B, secret)\n", key_bytes.size());
  std::printf("  → signer_pub.bin (%zu B)\n", pub_bytes.size());
  std::printf("  → signer_cache.bin (%zu B, the top tree above height %zu, for sign)\n",
              cache_bytes.size(), key.top_first());
  return 0;
}

int cmd_keygen(const Options& opt) {
  if (opt.scheme == Scheme::kStateless) return keygen_stateless(opt);
  SecureRng rng;
  SignerKey key;
  rng.fill_bytes(key.sk_seed, kSkSeedBytes);
  rng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
  key.height = static_cast<uint8_t>(kXmssH);
  key.next_leaf = 0;

  const auto t0 = Clock::now();
  const XmssKeyPair kp = XmssKeyPair::generate_from_seed_split(
      key.sk_seed, key.pk_seed, kXmssH, cache_split_height(kXmssH));
  const double keygen_ms = ms_since(t0);
  const Node root = kp.public_key();

  const auto key_bytes = write_signer_key(key);
  const auto pub_bytes = write_signer_pub({root, key.pk_seed, key.height});
  const auto cache_bytes = xmss_cache_bytes(kp, key);
  write_file(opt.path("signer_key.bin"), key_bytes);
  write_file(opt.path("signer_pub.bin"), pub_bytes);
  write_file(opt.path("signer_cache.bin"), cache_bytes);

  std::printf("keygen  ·  stateful  ·  XMSS h=%zu (%llu one-time signatures)  %.0f ms\n",
              kXmssH,
              static_cast<unsigned long long>(uint64_t{1} << kXmssH),
              keygen_ms);
  std::printf("  root     : %s\n", hex(root.data(), root.size()).c_str());
  std::printf("  pk_seed  : %s\n",
              hex(key.pk_seed.data(), key.pk_seed.size()).c_str());
  std::printf("  → signer_key.bin (%zu B, secret)\n", key_bytes.size());
  std::printf("  → signer_pub.bin (%zu B)\n", pub_bytes.size());
  std::printf("  → signer_cache.bin (%zu B, the tree above height %zu, for sign)\n",
              cache_bytes.size(), kp.subtree_height());
  return 0;
}

int cmd_commit(const Options& opt) {
  const Bytes msg = read_file(opt.msg_file);
  std::vector<uint8_t> pub_bytes;
  const Scheme scheme = read_pub_scheme(opt, "commit", pub_bytes);

  const Field F;
  SecureRng rng;
  const auto t0 = Clock::now();
  std::vector<uint8_t> com_bytes, state_bytes;
  if (scheme == Scheme::kStateful) {
    UserState state;
    com_bytes = write_commitment(user_commit(F, rng, msg, state));
    state_bytes = write_user_state(state);
  } else {
    slh::SlhUserState state;
    com_bytes = write_commitment(slh::slh_user_commit(F, rng, msg, state));
    state_bytes = slh::write_slh_user_state(state);
  }
  const double commit_ms = ms_since(t0);

  write_file(opt.path("commitment.bin"), com_bytes);
  write_file(opt.path("user_state.bin"), state_bytes);

  std::printf("commit  ·  %s  ·  message %zu B  %.1f ms\n", scheme_name(scheme),
              msg.size(), commit_ms);
  std::printf("  → commitment.bin (%zu B, send to the signer)\n",
              com_bytes.size());
  std::printf("  → user_state.bin (%zu B, secret)\n", state_bytes.size());
  return 0;
}

int sign_stateless(const Options& opt, const std::vector<uint8_t>& key_bytes) {
  slh::SlhParams p = kStatelessParams;
  const slh::SlhSecretKey sk = slh::read_slh_key(key_bytes, &p);
  const HmCommitment com = read_commitment(read_file(opt.path("commitment.bin")));

  SecureRng rng;
  const auto t0 = Clock::now();
  std::optional<slh::SlhKey> key = load_slh_cache(opt, p, sk);
  const bool from_cache = key.has_value();
  if (!from_cache) {
    key.emplace(slh::SlhKey::keygen_internal(p, sk.sk_seed, sk.sk_prf, sk.pk_seed));
    if (key->pk_root != sk.pk_root)
      throw std::runtime_error(
          "signer_key.bin is corrupt: it no longer yields its PK.root");
  }
  const slh::SlhSignature sig = slh::slh_signer_sign(*key, com, rng);
  const double sign_ms = ms_since(t0);
  const Hash d = slh::com_digest(com);
  if (!slh::slh_verify(p, sk.pk_seed, sk.pk_root, d.data(), d.size(), sig))
    throw std::runtime_error(
        "the signature does not verify (deleting signer_cache.bin makes sign "
        "rebuild it)");
  if (!from_cache) write_file(opt.path("signer_cache.bin"), slh_cache_bytes(*key));

  const auto sig_bytes = slh::write_slh_sig(p, sig);
  write_file(opt.path("slh_sig.bin"), sig_bytes);
  std::printf("sign  ·  stateless  ·  %s  %.0f ms\n", p.name, sign_ms);
  std::printf("  → slh_sig.bin (%zu B, send to the user)\n", sig_bytes.size());
  std::printf("  signer_key.bin unchanged; top tree %s\n", tree_source(from_cache));
  return 0;
}

int cmd_sign(const Options& opt) {
  const auto key_bytes = read_file(opt.path("signer_key.bin"));
  if (slh::has_magic(key_bytes, slh::kSlhKeyMagic))
    return sign_stateless(opt, key_bytes);
  SignerKey key = read_signer_key(key_bytes);
  require_fixed_height(key.height, "signer_key.bin");
  const HmCommitment com = read_commitment(read_file(opt.path("commitment.bin")));

  const uint64_t leaf = key.next_leaf;
  if (leaf >= uint64_t{1} << key.height) {
    std::fprintf(stderr, "sign: key exhausted\n");
    return 1;
  }
  const auto t0 = Clock::now();
  std::optional<XmssKeyPair> kp = load_xmss_cache(opt, key);
  const bool from_cache = kp.has_value();
  if (!from_cache)
    kp = XmssKeyPair::generate_from_seed_split(key.sk_seed, key.pk_seed, key.height,
                                               cache_split_height(key.height));
  const auto sig = signer_sign_with(*kp, key, com);
  const double sign_ms = ms_since(t0);
  if (!sig.has_value()) {
    std::fprintf(stderr,
                 "sign: the tree does not belong to this key (deleting "
                 "signer_cache.bin makes sign rebuild it)\n");
    return 1;
  }

  const auto sig_bytes = write_xmss_sig(*sig);
  write_file(opt.path("xmss_sig.bin"), sig_bytes);
  write_file(opt.path("signer_key.bin"), write_signer_key(key));
  if (!from_cache) write_file(opt.path("signer_cache.bin"), xmss_cache_bytes(*kp, key));

  std::printf("sign  ·  stateful  ·  leaf %llu of %llu  %.0f ms\n",
              static_cast<unsigned long long>(leaf),
              static_cast<unsigned long long>(uint64_t{1} << key.height), sign_ms);
  std::printf("  → xmss_sig.bin (%zu B, send to the user)\n", sig_bytes.size());
  std::printf("  signer_key.bin updated: next_leaf = %llu (%llu left)\n",
              static_cast<unsigned long long>(key.next_leaf),
              static_cast<unsigned long long>((uint64_t{1} << key.height) -
                                              key.next_leaf));
  std::printf("  tree: %s\n", tree_source(from_cache));
  return 0;
}

int prove_stateless(const Options& opt, const std::vector<uint8_t>& pub_bytes,
                    const std::vector<uint8_t>& state_bytes) {
  const Field F;
  slh::SlhParams p = kStatelessParams;
  const slh::SlhPublicKey pk = slh::read_slh_pub(pub_bytes, &p);
  const slh::SlhUserState state = slh::read_slh_user_state(state_bytes);
  const slh::SlhSignature sig =
      slh::read_slh_sig(read_file(opt.path("slh_sig.bin")), p);
  const Hash d = slh::com_digest(state.com);
  if (!slh::slh_verify(p, pk.pk_seed, pk.pk_root, d.data(), d.size(), sig)) {
    std::fprintf(stderr,
                 "prove: slh_sig.bin is not a signature on this commitment "
                 "under signer_pub.bin\n");
    return 1;
  }

  std::printf("prove  ·  stateless (%s)  ·  Longfellow (Ligero + sumcheck over "
              "GF(2^128))\n",
              p.name);
  auto circuit = open_slh_circuit(F, opt);
  const auto t0 = Clock::now();
  const auto proof = slh::slh_user_prove(F, p, *circuit, state, pk, sig);
  const double prove_ms = ms_since(t0);
  if (proof.empty()) {
    std::fprintf(stderr, "prove: prover failed (constraint violated?)\n");
    return 1;
  }
  write_file(opt.path("blind_sig.bin"), proof);
  std::printf("  → blind_sig.bin (%.1f KiB)  %.0f ms\n", proof.size() / 1024.0,
              prove_ms);
  return 0;
}

int cmd_prove(const Options& opt) {
  proofs::set_log_level(proofs::ERROR);
  std::vector<uint8_t> pub_bytes;
  const Scheme scheme = read_pub_scheme(opt, "prove", pub_bytes);
  const auto state_bytes = read_state_file(opt, scheme);
  if (scheme == Scheme::kStateless)
    return prove_stateless(opt, pub_bytes, state_bytes);
  const Field F;

  std::printf("prove  ·  stateful  ·  Longfellow (Ligero + sumcheck over GF(2^128))\n");
  auto circuit = open_circuit(F, opt);

  const UserState state = read_user_state(state_bytes);
  const SignerPub pub = read_signer_pub(pub_bytes);
  require_fixed_height(pub.height, "signer_pub.bin");

  const Hash d = hm_com_digest(state.com);
  const auto parsed = read_xmss_sig(read_file(opt.path("xmss_sig.bin")),
                                    pub.pk_seed, pub.height, d.data(),
                                    d.size());
  if (!parsed.has_value()) {
    std::fprintf(stderr,
                 "prove: xmss_sig.bin is not a signature on this commitment "
                 "under signer_pub.bin\n");
    return 1;
  }

  if (parsed->root != pub.root) {
    std::fprintf(stderr,
                 "prove: signature does not verify under signer_pub.bin "
                 "(recomputed root differs)\n");
    return 1;
  }

  const auto t0 = Clock::now();
  const BlindSignature bsig = user_prove(F, *circuit, state, *parsed);
  const double prove_ms = ms_since(t0);
  if (bsig.proof.empty()) {
    std::fprintf(stderr, "prove: prover failed (constraint violated?)\n");
    return 1;
  }

  const auto out_bytes = write_blind_sig(bsig);
  write_file(opt.path("blind_sig.bin"), out_bytes);
  std::printf("  → blind_sig.bin (%.1f KB)  %.0f ms\n",
              out_bytes.size() / 1024.0, prove_ms);
  return 0;
}

int verify_stateless(const Options& opt, const std::vector<uint8_t>& pub_bytes) {
  const Field F;
  slh::SlhParams p = kStatelessParams;
  const slh::SlhPublicKey pk = slh::read_slh_pub(pub_bytes, &p);
  std::printf("verify  ·  stateless (%s)  ·  Longfellow (Ligero + sumcheck over "
              "GF(2^128))\n",
              p.name);
  auto circuit = open_slh_circuit(F, opt);

  const Bytes msg = read_file(opt.msg_file);
  const auto proof = read_file(opt.path("blind_sig.bin"));
  const auto t0 = Clock::now();
  const bool ok = slh::slh_verify_blind(F, p, *circuit, pk, proof, msg);
  const double verify_ms = ms_since(t0);

  std::printf("  [%s]  %.1f KiB  %.0f ms\n", ok ? "PASS" : "FAIL",
              proof.size() / 1024.0, verify_ms);
  return ok ? 0 : 1;
}

int cmd_verify(const Options& opt) {
  proofs::set_log_level(proofs::ERROR);
  std::vector<uint8_t> pub_bytes;
  const Scheme scheme = read_pub_scheme(opt, "verify", pub_bytes);
  if (scheme == Scheme::kStateless) return verify_stateless(opt, pub_bytes);
  const Field F;

  std::printf("verify  ·  stateful  ·  Longfellow (Ligero + sumcheck over GF(2^128))\n");
  auto circuit = open_circuit(F, opt);

  const Bytes msg = read_file(opt.msg_file);
  const BlindSignature bsig = read_blind_sig(read_file(opt.path("blind_sig.bin")));
  const SignerPub pub = read_signer_pub(pub_bytes);
  require_fixed_height(pub.height, "signer_pub.bin");

  const auto t0 = Clock::now();
  const bool ok = verify_blind_sig(F, *circuit, pub, bsig, msg);
  const double verify_ms = ms_since(t0);

  std::printf("  [%s]  %.1f KiB  %.0f ms\n", ok ? "PASS" : "FAIL",
              bsig.proof.size() / 1024.0, verify_ms);
  return ok ? 0 : 1;
}

int run(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 1;
  }
  const std::string cmd = argv[1];
  if (cmd == "-h" || cmd == "--help" || cmd == "help") {
    usage();
    return 0;
  }

  Options opt;
  std::vector<std::string> positional;
  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](const char* what) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (arg == "--stateful" || arg == "--stateless") {
      const Scheme s = arg == "--stateful" ? Scheme::kStateful : Scheme::kStateless;
      if (opt.scheme && *opt.scheme != s)
        throw std::runtime_error("--stateful and --stateless are mutually exclusive");
      opt.scheme = s;
    } else if (arg == "-d" || arg == "--dir") {
      opt.dir = next("--dir");
    } else if (arg == "--circuit-cache") {
      opt.cache = next("--circuit-cache");
    } else if (arg == "-h" || arg == "--help") {
      usage();
      return 0;
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown option: " + arg);
    } else {
      positional.push_back(arg);
    }
  }

  const bool needs_msg = (cmd == "commit" || cmd == "verify");
  if (needs_msg) {
    if (positional.size() != 1) {
      std::fprintf(stderr, "%s needs exactly one <msg_file>\n", cmd.c_str());
      return 1;
    }
    opt.msg_file = positional[0];
  } else if (!positional.empty()) {
    std::fprintf(stderr, "%s takes no positional arguments\n", cmd.c_str());
    return 1;
  }
  if (opt.scheme && cmd != "keygen")
    throw std::runtime_error("--stateful and --stateless are keygen options; " +
                             cmd + " follows the key files");

  if (cmd == "keygen") return cmd_keygen(opt);
  if (cmd == "commit") return cmd_commit(opt);
  if (cmd == "sign") return cmd_sign(opt);
  if (cmd == "prove") return cmd_prove(opt);
  if (cmd == "verify") return cmd_verify(opt);

  std::fprintf(stderr, "unknown command: %s\n\n", cmd.c_str());
  usage();
  return 1;
}

}
}

int main(int argc, char** argv) {
  try {
    return blind_longfellow::run(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
