#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "arrays/dense.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "util/log.h"
#include "util/panic.h"

#include "circuit/blind_stmt.h"
#include "circuit_cache.h"
#include "commitment.h"
#include "field.h"
#include "native_witness.h"
#include "protocol.h"
#include "prover.h"
#include "rng.h"
#include "sha.h"
#include "verifier.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {

constexpr size_t kTestXmssH = 10;
namespace {

using proofs::Circuit;
using EvalBackend = proofs::EvaluationBackend<Field>;
using EvalLogic = proofs::Logic<Field, EvalBackend>;
using Encoder = proofs::BitPluckerEncoder<Field, kPluckerSize>;

struct Tally {
  int pass = 0;
  int fail = 0;
  void record(const char* name, bool ok) {
    (ok ? pass : fail)++;
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
  }
};

Bytes str_bytes(const char* s) {
  return Bytes(reinterpret_cast<const uint8_t*>(s),
               reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
}

Hash msg32(const char* s) {
  return sha256(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
}

bool eq_com(const HmCommitment& x, const HmCommitment& y) {
  return x.a == y.a && x.b == y.b && x.y == y.y;
}

std::vector<uint8_t> from_hex(const char* hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; hex[2 * i] != '\0'; ++i) {
    unsigned v = 0;
    std::sscanf(hex + 2 * i, "%2x", &v);
    out.push_back(static_cast<uint8_t>(v));
  }
  return out;
}

struct EncodingVector {
  const char* digest_hex;
  uint8_t coords[kLen];
  bool leftover_ok;
  int sum;
};
constexpr EncodingVector kEncodingVectors[] = {
    { "971f3566ad3fd575f6bf9699dfc2f17d", {7,2,6,7,1,2,5,1,6,4,5,6,2,7,7,1,5,2,7,2,7,6,6,7,7,3,5,5,4,1,3,6,7,5,5,0,6,1,6,7,6,7}, true, 195 },
    { "77a8d6453a525f4cffbf2fecbfdf3e4b", {7,6,1,4,2,5,5,6,5,0,1,5,3,4,4,2,7,3,1,6,4,7,7,7,7,3,7,3,1,4,5,7,7,3,7,7,6,6,7,4,5,4}, true, 195 },
    { "6cb4abdd5dba86439fdf9669d97eff7e", {4,5,1,2,3,7,2,5,5,3,7,6,5,4,6,5,6,0,6,1,4,7,3,6,7,5,5,5,4,1,5,5,4,5,5,7,3,7,7,3,7,7}, true, 195 },
    { "fd5cf0f48ff1b749dbddff097afc5c7a", {5,7,3,6,5,0,4,7,4,6,7,7,0,3,4,7,7,6,6,4,4,3,3,7,6,5,7,7,7,1,1,0,5,7,0,7,7,4,3,1,5,7}, true, 195 },
    { "004dab8b0c50fb0c01a98f974357defe", {0,0,4,6,4,6,2,5,3,1,2,6,0,0,4,2,3,7,3,6,0,1,0,4,4,2,7,3,4,7,2,6,1,4,6,5,2,6,3,3,7,7}, false, 148 },
    { "3807a92b5d7610d9f2c55a7c246ba85c", {0,7,4,3,0,2,2,5,3,5,4,6,5,4,5,3,0,2,4,4,5,2,6,7,2,4,5,6,2,4,7,1,2,2,6,2,3,0,5,2,6,5}, false, 152 },
    { "cdf9af0b35b13c3a6655773165e714d4", {5,1,7,4,7,7,3,5,3,1,4,2,3,2,4,5,4,7,0,5,3,6,4,5,2,5,6,5,3,1,6,4,2,6,6,1,7,4,2,0,2,5}, false, 164 },
    { "b77215996f0bc725323951062956b656", {7,6,2,1,7,2,5,0,1,3,6,7,6,6,2,0,7,0,7,2,2,2,6,4,4,3,2,4,2,6,0,4,4,2,4,5,2,6,6,2,3,5}, true, 155 },
    { "00000000000000000000000000000000", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, true, 0 },
    { "ffffffffffffffffffffffffffffffff", {7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7}, false, 294 },
    { "58845db1462027f0d9c6bf1c9d7ac9a3", {0,3,1,2,0,3,7,2,1,6,2,3,4,0,0,1,7,4,0,0,7,1,3,3,3,4,7,7,5,4,3,4,6,1,5,6,3,1,1,7,1,2}, false, 130 },
    { "b65c9fa346dff91728785b7ce60e53e3", {6,6,2,6,5,6,7,4,3,4,2,3,4,6,7,6,1,7,7,3,1,0,5,0,4,7,6,6,2,4,7,1,3,6,5,3,0,3,2,5,1,6}, false, 172 },
    { "036e40178dfbf8deffe839d5f3c62db9", {3,0,0,7,6,0,0,2,7,2,4,6,0,7,6,7,0,7,3,7,5,7,7,3,4,6,3,6,1,5,2,7,1,7,5,1,6,5,5,4,4,3}, false, 171 },
    { "9cc5744ec3d0b116b8196eba65336ba4", {4,3,6,2,4,1,5,3,6,1,5,1,4,1,4,6,1,6,2,3,1,0,7,6,4,1,4,3,3,2,7,6,2,6,6,4,1,3,5,1,2,2}, false, 144 },
    { "149021e336e9359e626baa7330773505", {4,2,0,0,1,3,0,1,3,4,3,3,3,2,2,7,5,6,0,7,1,2,4,5,5,6,4,2,5,3,6,1,0,3,6,5,3,5,6,4,2,0}, false, 134 },
    { "7bf340a276c03bf5b09ff145cb49dfd2", {3,7,5,1,7,1,0,2,2,4,2,3,7,0,0,6,3,7,4,2,7,0,6,6,7,1,3,4,7,5,0,5,5,4,3,2,2,7,3,3,1,5}, false, 152 },
};

void test_sha_and_codeword(Tally& t) {

  {
    std::array<uint8_t, 300> entropy{};
    SecureRng rng;
    rng.fill_bytes(entropy.data(), entropy.size());
    bool any_nonzero = false;
    for (uint8_t byte : entropy) any_nonzero |= byte != 0;
    t.record("OpenSSL RAND_bytes supplies randomness", any_nonzero);
  }

  {
    std::array<uint8_t, 20> key;
    key.fill(0x0b);
    static constexpr uint8_t kData[] = "Hi There";
    static constexpr Hash kExpected = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    t.record("HMAC-SHA-256 matches RFC 4231 test vector",
             hmac_sha256(key.data(), key.size(), kData,
                         sizeof(kData) - 1) == kExpected);
  }

  const PkSeed pk_seed = [] { PkSeed h; h.fill(0x33); return h; }();
  const Bytes param = build_wots_domain_param(pk_seed);
  t.record("domain param has the configured width", param.size() == kPkSeedBytes);

  const uint32_t epoch = 5;

  {
    Node start; start.fill(0x77);
    const size_t chain_idx = 5, start_pos = 2, steps = 4;
    Node iter = start;
    for (size_t i = 0; i < steps; ++i)
      iter = hash_chain(param, epoch, iter, chain_idx, start_pos + i + 1);
    t.record("hash_chain_multi == iterated hash_chain",
             hash_chain_multi(param, epoch, start, chain_idx, start_pos, steps) ==
                 iter);
  }

  {
    Node h; h.fill(0x42);
    Bytes pre = param;
    pre.push_back(0x00);
    for (size_t k = 0; k < kEpochBytes; ++k)
      pre.push_back(static_cast<uint8_t>((epoch >> (8 * k)) & 0xff));
    pre.insert(pre.end(), h.begin(), h.end());
    pre.push_back(3);
    pre.push_back(7);
    t.record("chain hash matches direct SHA-256 of preimage",
             hash_chain(param, epoch, h, 3, 7) == sha256_node(pre));
  }

  {
    Node left, right;
    for (size_t i = 0; i < kNodeBytes; ++i) {
      left[i] = static_cast<uint8_t>(i);
      right[i] = static_cast<uint8_t>(200 - i);
    }
    const Bytes pre = build_tree_hash(param, left, right, 3, 0x0102);

    uint8_t block[64] = {};
    std::memcpy(block, pre.data() + kTreePrefixBytes, kTreeTailLen);
    block[kTreeTailLen] = 0x80;
    const uint64_t bitlen = static_cast<uint64_t>(kTreeLen) * 8;
    for (size_t k = 0; k < 8; ++k)
      block[63 - k] = static_cast<uint8_t>((bitlen >> (8 * k)) & 0xff);

    uint32_t in[16], outw[48], oute[64], outa[64], h1[8];
    for (size_t i = 0; i < 16; ++i)
      in[i] = proofs::SHA256_ru32be(block + 4 * i);
    const Midstate mid = tree_midstate(param);
    proofs::FlatSHA256Witness::transform_and_witness_block(in, mid.data(), outw,
                                                           oute, outa, h1);
    Node hoisted;
    for (size_t i = 0; i < kNodeBytes; ++i)
      hoisted[i] = static_cast<uint8_t>(h1[i / 4] >> (8 * (3 - i % 4)));

    t.record("tree preimage is a hoisted prefix plus one tail block",
             pre.size() == kTreeLen && kTreeTailLen + 9 <= 64);
    t.record("hoisted tree prefix reproduces plain SHA-256",
             hoisted == hash_tree_node(param, left, right, 3, 0x0102));
  }

  {
    uint8_t hash[16];
    std::memset(hash, 0xff, sizeof(hash));
    bool leftover_ok = true;
    const auto coords = extract_coords(hash, &leftover_ok);
    bool all_max = coords.size() == kLen;
    for (uint8_t c : coords) all_max = all_max && c == kW - 1;
    t.record("extract_coords: all-ones digest is all-maximal", all_max);
    t.record("extract_coords: a set leftover bit is rejected", !leftover_ok);

    std::memset(hash, 0, sizeof(hash));
    hash[0] = 0xC0;
    hash[1] = 0x01;
    const auto straddle = extract_coords(hash, &leftover_ok);
    t.record("extract_coords: a coordinate straddling a byte decodes",
             straddle[2] == 7 && straddle[0] == 0 && straddle[1] == 0);

    std::memset(hash, 0, sizeof(hash));
    hash[8] = 0x05;
    const auto second_word = extract_coords(hash, &leftover_ok);
    t.record("extract_coords: the second digest word opens at coordinate 21",
             second_word[21] == 5 && second_word[20] == 0 && leftover_ok);

    std::memset(hash, 0, sizeof(hash));
    hash[7] = 0x80;
    extract_coords(hash, &leftover_ok);
    const bool bit63_rejected = !leftover_ok;
    std::memset(hash, 0, sizeof(hash));
    hash[15] = 0x80;
    extract_coords(hash, &leftover_ok);
    t.record("extract_coords: either leftover bit alone is rejected",
             bit63_rejected && !leftover_ok);

    bool vectors_ok = true;
    for (const EncodingVector& v : kEncodingVectors) {
      const std::vector<uint8_t> digest = from_hex(v.digest_hex);
      bool ok = false;
      const auto got = extract_coords(digest.data(), &ok);
      int sum = 0;
      for (uint8_t c : got) sum += c;
      const bool match =
          digest.size() == kMsgHashBytes && got.size() == kLen &&
          std::memcmp(got.data(), v.coords, kLen) == 0 &&
          ok == v.leftover_ok && sum == v.sum;
      if (!match) std::printf("  vector %s disagrees with binius64\n", v.digest_hex);
      vectors_ok = vectors_ok && match;
    }
    t.record("codeword extraction matches binius64's wots_encode", vectors_ok);
  }
}

void test_wots(Tally& t) {
  const WinternitzSpec spec = xmss_wots_spec();
  t.record("WinternitzSpec dimension=42, chain_len=8",
           spec.dimension() == 42 && spec.chain_len() == 8);

  DeterministicRng rng(42);
  const Bytes param(kPkSeedBytes, 0xAA);
  const uint32_t epoch = 0;

  const std::vector<Node> sk = generate_wots_secret_key(rng);
  const std::vector<Node> pk = compute_wots_public_key(param, epoch, sk);

  const std::vector<uint8_t> zeros(kLen, 0);
  const std::vector<Node> sig0 = compute_wots_signature(param, epoch, sk, zeros);
  t.record("WOTS+ coord=0 ⇒ signature == secret key", sig0 == sk);
  t.record("WOTS+ pk(sig|coord=0) == pk(sk)",
           compute_wots_pk_hashes(param, epoch, sig0, zeros) == pk);

  const std::vector<uint8_t> maxc(kLen, static_cast<uint8_t>(kW - 1));
  const std::vector<Node> sigm = compute_wots_signature(param, epoch, sk, maxc);
  t.record("WOTS+ pk(sig|coord=W-1) == pk(sk)",
           compute_wots_pk_hashes(param, epoch, sigm, maxc) == pk);

  t.record("WOTS+ public key is epoch-separated",
           compute_wots_public_key(param, epoch + 1, sk) != pk);

  const Hash m = msg32("wots grind message");
  const GrindResult grind =
      grind_nonce(spec, rng, param, epoch, m.data(), m.size());
  uint64_t sum = 0;
  for (uint8_t c : grind.coords) sum += c;
  const bool grind_ok =
      (sum == spec.target_sum) && grind.nonce.size() == kNonceLength;
  t.record("grind_nonce coords sum to target_sum", grind_ok);

  const WotsSigningData data =
      WotsSigningData::generate(spec, rng, param, epoch, m.data(), m.size());
  bool data_ok = data.sig_hashes.size() == kLen &&
                 data.pk_hashes.size() == kLen &&
                 compute_wots_pk_hashes(param, epoch, data.sig_hashes,
                                        data.coords) == data.pk_hashes;
  t.record("WotsSigningData::generate self-consistent", data_ok);
}

void test_xmss(Tally& t) {
  const WinternitzSpec spec = xmss_wots_spec();
  DeterministicRng rng(0xB11Ad);

  PkSeed pk_seed;
  rng.fill_bytes(pk_seed.data(), pk_seed.size());

  std::printf("  (XMSS keygen: %d leaves...)\n", 1 << kTestXmssH);
  XmssKeyPair kp = XmssKeyPair::generate(rng, pk_seed, kTestXmssH);
  t.record("XMSS keygen: 1024 leaves available", kp.remaining() == 1024);

  {
    std::array<uint8_t, kSkSeedBytes> seed_a{};
    seed_a.fill(0x11);
    auto seed_b = seed_a;
    seed_b.back() ^= 1;
    PkSeed vector_pk_seed;
    vector_pk_seed.fill(0x22);

    static constexpr Node kExpectedRoot = {
        0x9f, 0x15, 0x27, 0x7d, 0x0b, 0x43, 0x82, 0x09,
        0x36, 0xe9, 0xc0, 0xf0, 0x25, 0x6f, 0xa5, 0x4a,
    };
    const Node root_a = XmssKeyPair::generate_from_seed(
                            seed_a.data(), vector_pk_seed, kTestXmssH)
                            .public_key();
    const Node root_b = XmssKeyPair::generate_from_seed(
                            seed_b.data(), vector_pk_seed, kTestXmssH)
                            .public_key();
    t.record("XMSS PRF derivation matches fixed root vector",
             root_a == kExpectedRoot);
    t.record("XMSS key derivation uses all 32 seed bytes", root_a != root_b);
  }

  const Hash m1 = msg32("first message to sign");
  auto sig1 = kp.sign(spec, rng, m1.data(), m1.size());
  bool shape_ok = sig1.has_value() &&
                  sig1->wots.sig_hashes.size() == kLen &&
                  sig1->wots.pk_hashes.size() == kLen &&
                  sig1->xmss_calls.size() == kXmssH &&
                  sig1->leaf_index == 0 && sig1->root == kp.public_key();
  t.record("XMSS sign #1: correct shape, root == pk", shape_ok);
  t.record("XMSS leaf counter advanced", kp.remaining() == 1023);

  t.record("signature shape: 42 chain starts of 16 B, 32 path nodes of 16 B, "
           "24 B nonce",
           kLen == 42 && kNodeBytes == 16 && kXmssH == 32 &&
               kNonceLength == 24 && kPkSeedBytes == 16);

  {
    const uint32_t resume = kp.next_leaf();
    bool all_ground = true;
    for (int i = 0; i < 100; ++i) {
      const Hash m = msg32((std::string("grind budget ") + std::to_string(i)).c_str());
      auto s = kp.sign(spec, rng, m.data(), m.size());
      all_ground = all_ground && s.has_value() &&
                   xmss_verify(spec, pk_seed, kp.public_key(), s->leaf_index,
                               m.data(), m.size(), s->wots.nonce,
                               s->wots.sig_hashes, s->auth_path);
    }
    t.record("grinding succeeds over 100 signatures", all_ground);
    kp.set_next_leaf(resume);
  }

  bool v1 = sig1.has_value() &&
            xmss_verify(spec, pk_seed, kp.public_key(), sig1->leaf_index,
                        m1.data(), m1.size(), sig1->wots.nonce,
                        sig1->wots.sig_hashes, sig1->auth_path);
  t.record("XMSS verify accepts honest signature", v1);

  const Hash m2 = msg32("second message to sign");
  auto sig2 = kp.sign(spec, rng, m2.data(), m2.size());
  bool v2 = sig2.has_value() && sig2->leaf_index == 1 &&
            sig2->root == kp.public_key() &&
            xmss_verify(spec, pk_seed, kp.public_key(), sig2->leaf_index,
                        m2.data(), m2.size(), sig2->wots.nonce,
                        sig2->wots.sig_hashes, sig2->auth_path);
  t.record("XMSS sign+verify #2 on next leaf (same root)", v2);

  proofs::check(sig1.has_value(), "sig1");
  const auto& s = *sig1;

  {
    auto bad = s.wots.sig_hashes;
    bad[0][0] ^= 1;
    t.record("XMSS verify rejects tampered WOTS+ signature",
             !xmss_verify(spec, pk_seed, kp.public_key(), s.leaf_index,
                          m1.data(), m1.size(), s.wots.nonce, bad, s.auth_path));
  }
  {
    AuthPath bad = s.auth_path;
    bad[0][0] ^= 1;
    t.record("XMSS verify rejects tampered auth path",
             !xmss_verify(spec, pk_seed, kp.public_key(), s.leaf_index,
                          m1.data(), m1.size(), s.wots.nonce,
                          s.wots.sig_hashes, bad));
  }
  {
    const Hash wrong = msg32("a different message entirely");
    t.record("XMSS verify rejects wrong message",
             !xmss_verify(spec, pk_seed, kp.public_key(), s.leaf_index,
                          wrong.data(), wrong.size(), s.wots.nonce,
                          s.wots.sig_hashes, s.auth_path));
  }
  {
    Bytes bad_nonce = s.wots.nonce;
    bad_nonce[0] ^= 1;
    t.record("XMSS verify rejects wrong nonce",
             !xmss_verify(spec, pk_seed, kp.public_key(), s.leaf_index,
                          m1.data(), m1.size(), bad_nonce, s.wots.sig_hashes,
                          s.auth_path));
  }
  {
    t.record("XMSS verify rejects wrong leaf index",
             !xmss_verify(spec, pk_seed, kp.public_key(), s.leaf_index + 1,
                          m1.data(), m1.size(), s.wots.nonce,
                          s.wots.sig_hashes, s.auth_path));
  }

  {
    std::array<uint8_t, kSkSeedBytes> split_seed{};
    split_seed.fill(0x5B);
    PkSeed split_pk;
    split_pk.fill(0x6C);
    const Bytes param = build_wots_domain_param(split_pk);

    bool split_ok = true;
    for (size_t height = 1; height <= 5 && split_ok; ++height) {

      std::vector<std::vector<Node>> flat;
      {

        const XmssKeyPair probe =
            XmssKeyPair::generate_from_seed(split_seed.data(), split_pk, height);
        std::vector<Node> leaves;
        for (uint32_t e = 0; e < 1u << height; ++e) {
          const std::vector<Node> sk = probe.wots_secret_key(e);
          leaves.push_back(hash_public_key(
              param, e, compute_wots_public_key(param, e, sk)));
        }
        flat.push_back(std::move(leaves));
        for (size_t h = 1; h <= height; ++h) {
          std::vector<Node> level;
          for (size_t i = 0; i < size_t{1} << (height - h); ++i) {
            level.push_back(hash_tree_node(param, flat[h - 1][2 * i],
                                           flat[h - 1][2 * i + 1],
                                           static_cast<uint32_t>(h - 1),
                                           static_cast<uint32_t>(i)));
          }
          flat.push_back(std::move(level));
        }
      }

      for (size_t sub = 1; sub <= height && split_ok; ++sub) {

        XmssKeyPair split = XmssKeyPair::generate_from_seed_split(
            split_seed.data(), split_pk, height, sub);
        for (uint32_t leaf = 0; leaf < 1u << height && split_ok; ++leaf) {
          split.set_next_leaf(leaf);
          DeterministicRng srng(0x5A11 + leaf);
          const Hash m = msg32("split traversal");
          auto sig = split.sign(spec, srng, m.data(), m.size());
          if (!sig.has_value()) {
            std::printf("    (h=%zu sub=%zu leaf %u: no signature)\n", height,
                        sub, leaf);
            split_ok = false;
            break;
          }
          if (sig->leaf != flat[0][leaf]) {
            std::printf("    (h=%zu sub=%zu leaf %u: wrong leaf value)\n",
                        height, sub, leaf);
            split_ok = false;
            break;
          }
          uint32_t idx = leaf;
          for (size_t h = 0; h < height; ++h) {
            if (sig->auth_path[h] != flat[h][idx ^ 1]) {
              std::printf("    (h=%zu sub=%zu leaf %u: level %zu sibling)\n",
                          height, sub, leaf, h);
              split_ok = false;
              break;
            }
            idx >>= 1;
          }
          if (split_ok &&
              !xmss_verify(spec, split_pk, split.public_key(), leaf, m.data(),
                           m.size(), sig->wots.nonce, sig->wots.sig_hashes,
                           sig->auth_path)) {
            std::printf("    (h=%zu sub=%zu leaf %u: does not verify)\n", height,
                        sub, leaf);
            split_ok = false;
          }
        }
      }
    }
    t.record(
        "XMSS split traversal reproduces a materialized tree at every height "
        "and split",
        split_ok);
  }
}

void test_signer_end_to_end(const Field& F, Tally& t) {
  const WinternitzSpec spec = xmss_wots_spec();
  DeterministicRng rng(0x516E);

  const Bytes user_msg = str_bytes("blind me");
  auto [com, opening] = sample_commitment(F, rng, user_msg);

  PkSeed pk_seed;
  rng.fill_bytes(pk_seed.data(), pk_seed.size());
  XmssKeyPair signer = XmssKeyPair::generate(rng, pk_seed, kTestXmssH);

  const Hash d = hm_com_digest(com);
  auto sig = signer.sign(spec, rng, d.data(), d.size());

  const bool ok =
      sig.has_value() &&
      xmss_verify(spec, pk_seed, signer.public_key(), sig->leaf_index,
                  d.data(), d.size(), sig->wots.nonce,
                  sig->wots.sig_hashes, sig->auth_path) &&
      verify_hm_opening(F, com, user_msg, opening.r);
  t.record("end-to-end: commit → sign com digest → verify both halves", ok);
}

void test_commitment(const Field& F, Tally& t) {
  const Bytes msg = str_bytes("commitment test message");

  DeterministicRng rng(0xC0117);
  auto [com, opening] = sample_commitment(F, rng, msg);

  t.record("verify_hm_opening accepts honest opening",
           verify_hm_opening(F, com, msg, opening.r));

  {
    const HmCommitment com2 = hm_commit(F, msg, com.a, opening.r);
    t.record("hm_commit deterministic",
             com2.a == com.a && com2.b == com.b && com2.y == com.y);
  }

  t.record("verify_hm_opening rejects wrong message",
           !verify_hm_opening(F, com, str_bytes("a different message"),
                              opening.r));

  {
    auto r = opening.r;
    r[3][0] ^= 0x01;
    t.record("verify_hm_opening rejects tampered r[3]",
             !verify_hm_opening(F, com, msg, r));
  }
  {
    auto r = opening.r;
    std::swap(r[0], r[1]);
    t.record("verify_hm_opening rejects permuted r",
             !verify_hm_opening(F, com, msg, r));
  }
  {
    HmCommitment bad = com;
    bad.b[1][0] ^= 0x01;
    t.record("verify_hm_opening rejects tampered b",
             !verify_hm_opening(F, bad, msg, opening.r));
  }
  {
    HmCommitment bad = com;
    bad.a[0][2][0] ^= 0x01;
    t.record("verify_hm_opening rejects tampered a",
             !verify_hm_opening(F, bad, msg, opening.r));
  }
  {
    HmCommitment bad = com;
    bad.y[0] ^= 0x01;
    t.record("verify_hm_opening rejects mismatched y",
             !verify_hm_opening(F, bad, msg, opening.r));
  }
  {

    const Hash d1 = hm_com_digest(com);
    const Hash d2 = hm_com_digest(hm_commit(F, str_bytes("other"), com.a,
                                            opening.r));
    t.record("commitment digest differs across messages", !(d1 == d2));
  }
}

void test_serialization(const Field& F, Tally& t) {
  {
    SignerKey key;
    DeterministicRng rng(0x5E1);
    rng.fill_bytes(key.sk_seed, kSkSeedBytes);
    rng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
    key.height = static_cast<uint8_t>(kTestXmssH);
    key.next_leaf = 0x0123456789ABCDEFull;
    const SignerKey back = read_signer_key(write_signer_key(key));
    t.record("signer_key round-trips",
             std::memcmp(back.sk_seed, key.sk_seed, kSkSeedBytes) == 0 &&
                 back.pk_seed == key.pk_seed &&
                 back.height == key.height &&
                 back.next_leaf == key.next_leaf);
  }
  {
    Node root;
    PkSeed pk_seed;
    for (size_t i = 0; i < root.size(); ++i) root[i] = i;
    for (size_t i = 0; i < pk_seed.size(); ++i) pk_seed[i] = 0xA0 + i;
    const auto [r2, p2] = read_signer_pub(write_signer_pub(root, pk_seed));
    t.record("signer_pub round-trips", r2 == root && p2 == pk_seed);
  }
  {
    const Bytes msg = str_bytes("serialize me");
    DeterministicRng rng(0xABCD);
    UserState state;
    const HmCommitment com = user_commit(F, rng, msg, state);

    const HmCommitment com_back = read_commitment(write_commitment(com));
    t.record("commitment round-trips", eq_com(com_back, com));

    const UserState st_back = read_user_state(write_user_state(state));
    t.record("user_state round-trips",
             st_back.msg == state.msg && eq_com(st_back.com, state.com) &&
                 st_back.opening.r == state.opening.r);
  }
  {
    SignerKey key;
    DeterministicRng rng(0x9001);
    rng.fill_bytes(key.sk_seed, kSkSeedBytes);
    rng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
    key.height = static_cast<uint8_t>(kTestXmssH);
    key.next_leaf = 0;

    DeterministicRng urng(0x7);
    UserState state;
    const HmCommitment com = user_commit(F, urng, str_bytes("xmss serialize"),
                                         state);
    const auto sig = signer_sign(key, com);
    bool ok = sig.has_value();
    if (ok) {

      const std::vector<uint8_t> wire = write_xmss_sig(*sig);
      t.record("xmss_sig is the minimal 1212 B", wire.size() == 1212);
      const Hash d = hm_com_digest(com);
      const auto parsed = read_xmss_sig(wire, key.pk_seed, d.data(), d.size());
      t.record("xmss_sig expands", parsed.has_value());

      PkSeed wrong_seed = key.pk_seed;
      wrong_seed[0] ^= 1;
      t.record("wrong pk_seed rejected",
               !read_xmss_sig(wire, wrong_seed, d.data(), d.size()).has_value());
      std::vector<uint8_t> truncated(wire.begin(), wire.end() - 1);
      t.record("truncated xmss_sig rejected",
               !read_xmss_sig(truncated, key.pk_seed, d.data(), d.size())
                    .has_value());
      std::vector<uint8_t> tampered = wire;
      tampered[4 + kNonceLength] ^= 1;
      const auto bad = read_xmss_sig(tampered, key.pk_seed, d.data(), d.size());
      t.record("tampered sig_hashes yields a different root",
               !bad.has_value() || bad->root != sig->root);

      ok = parsed.has_value();
      if (ok) {
        const XmssSignature& back = *parsed;
        ok = back.leaf_index == sig->leaf_index && back.root == sig->root &&
             back.leaf == sig->leaf && back.wots.nonce == sig->wots.nonce &&
             back.wots.message_hash == sig->wots.message_hash &&
             back.wots.coords == sig->wots.coords &&
             back.wots.sig_hashes == sig->wots.sig_hashes &&
             back.wots.pk_hashes == sig->wots.pk_hashes &&
             back.auth_path == sig->auth_path &&
             back.xmss_calls.size() == sig->xmss_calls.size();
        for (size_t h = 0; ok && h < back.xmss_calls.size(); ++h) {
          const auto& x = back.xmss_calls[h];
          const auto& y = sig->xmss_calls[h];
          ok = x.left == y.left && x.right == y.right && x.output == y.output &&
               x.node_is_left == y.node_is_left && x.height == y.height &&
               x.node_index == y.node_index;
        }
      }
    }
    t.record("xmss_sig round-trips", ok);
  }
  {
    BlindSignature bsig;
    bsig.proof = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22};
    const BlindSignature back = read_blind_sig(write_blind_sig(bsig));
    t.record("blind_sig round-trips", back.proof == bsig.proof);
  }
}

template <class L_>
typename L_::v256 digest_to_v256(const L_& L, const uint8_t d[kHashBytes]) {
  typename L_::v256 v;
  for (size_t j = 0; j < 256; ++j)
    v[j] = L.bit((d[(255 - j) / 8] >> (j % 8)) & 1);
  return v;
}

template <class L_>
typename L_::template bitvec<kNodeBits> node_to_nodew(
    const L_& L, const uint8_t d[kNodeBytes]) {
  typename L_::template bitvec<kNodeBits> v;
  for (size_t i = 0; i < kNodeBits; ++i)
    v[i] = L.bit((d[kNodeBytes - 1 - i / 8] >> (i % 8)) & 1);
  return v;
}

template <class L_>
typename proofs::FlatSHA256Circuit<L_, proofs::BitPlucker<L_, kPluckerSize>>::
    packed_v32
    eval_packed_v32(const L_& L, Encoder& enc, uint32_t v) {
  using PV = typename proofs::FlatSHA256Circuit<
      L_, proofs::BitPlucker<L_, kPluckerSize>>::packed_v32;
  const auto elts = enc.mkpacked_v32(v);
  PV pv;
  for (size_t j = 0; j < pv.size(); ++j) pv[j] = L.konst(elts[j]);
  return pv;
}

template <class L_>
void fill_eval_bw(
    typename proofs::FlatSHA256Circuit<
        L_, proofs::BitPlucker<L_, kPluckerSize>>::BlockWitness& bw,
    const L_& L, Encoder& enc, const NativeBW& nbw) {
  for (size_t k = 0; k < 48; ++k) bw.outw[k] = eval_packed_v32(L, enc, nbw.outw[k]);
  for (size_t k = 0; k < 64; ++k) {
    bw.oute[k] = eval_packed_v32(L, enc, nbw.oute[k]);
    bw.outa[k] = eval_packed_v32(L, enc, nbw.outa[k]);
  }
  for (size_t k = 0; k < 8; ++k) bw.h1[k] = eval_packed_v32(L, enc, nbw.h1[k]);
}

std::unique_ptr<StatementWires<EvalLogic>> fill_eval_wires(
    const EvalLogic& L, const Field& F, const NativeWitness& nw) {
  Encoder enc(F);
  auto W = std::make_unique<StatementWires<EvalLogic>>();

  for (size_t j = 0; j < kHashBytes; ++j)
    W->commit.mhat[j] = L.template vbit<8>(nw.m_hat[j]);

  for (size_t j = 0; j < kDomainParamLen; ++j)
    W->shared.domain_param[j] = L.template vbit<8>(nw.domain_param[j]);
  W->xmss.xmss_root = node_to_nodew(L, nw.xmss_root.data());
  const Midstate mid = tree_midstate(
      Bytes(nw.domain_param, nw.domain_param + kDomainParamLen));
  for (size_t k = 0; k < 8; ++k)
    W->shared.merkle_midstate[k] = L.template vbit<32>(mid[k]);

  for (size_t i = 0; i < kNNonce; ++i)
    for (size_t j = 0; j < kFeBytes; ++j)
      W->commit.r_bytes[i][j] = L.template vbit<8>(nw.r_bytes[i][j]);
  for (size_t k = 0; k < kNLines; ++k) {
    for (size_t i = 0; i < kNNonce; ++i)
      for (size_t j = 0; j < kFeBytes; ++j)
        W->commit.a_bytes[k][i][j] = L.template vbit<8>(nw.a_bytes[k][i][j]);
    for (size_t j = 0; j < kFeBytes; ++j)
      W->commit.b_bytes[k][j] = L.template vbit<8>(nw.b_bytes[k][j]);
  }
  for (size_t j = 0; j < kRevealBlocks; ++j)
    fill_eval_bw(W->commit.reveal_bw[j], L, enc, nw.reveal_bw[j]);
  for (size_t j = 0; j < kComBlocks; ++j)
    fill_eval_bw(W->commit.com_bw[j], L, enc, nw.com_bw[j]);

  for (size_t j = 0; j < kNonceLength; ++j)
    W->xmss.nonce[j] = L.template vbit<8>(nw.nonce[j]);
  for (size_t j = 0; j < kMsgBlocks; ++j)
    fill_eval_bw(W->xmss.msg_bw[j], L, enc, nw.msg_bw[j]);

  for (size_t i = 0; i < kLen; ++i) {
    W->xmss.sig_hash[i] = node_to_nodew(L, nw.sig_hashes[i].data());
    W->xmss.pk_hash[i] = node_to_nodew(L, nw.pk_hashes[i].data());
  }
  for (size_t j = 0; j < kPooledChainLen; ++j) {
    W->xmss.step_in[j] = node_to_nodew(L, nw.step_in[j].data());
    W->xmss.step_chain_idx[j] = L.template vbit<8>(nw.step_chain_idx[j]);
    W->xmss.step_count[j] = L.template vbit<8>(nw.step_count[j]);
    W->xmss.step_position[j] = L.template vbit<8>(nw.step_position[j]);
    for (size_t b = 0; b < kChainBlocks; ++b)
      fill_eval_bw(W->xmss.step_bw[j][b], L, enc, nw.step_bw[j][b]);
  }

  for (size_t j = 0; j < kLtreeBlocks; ++j)
    fill_eval_bw(W->xmss.leaf_bw[j], L, enc, nw.leaf_bw[j]);

  W->leaf_index = L.template vbit<32>(nw.leaf_index);
  for (size_t h = 0; h < kXmssH; ++h) {
    W->xmss.auth[h] = node_to_nodew(L, nw.auth_path[h].data());
    for (size_t b = 0; b < kTreeBlocks; ++b)
      fill_eval_bw(W->xmss.merkle_bw[h][b], L, enc, nw.merkle_bw[h][b]);
  }
  return W;
}

[[gnu::noinline]]
bool eval_validate(const Field& F, const NativeWitness& nw,
                   const Elt pow_x[kBits128]) {
  EvalBackend ebk(F,  false);
  EvalLogic L(&ebk, F);
  const auto W = fill_eval_wires(L, F, nw);
  assert_statement(L, F, *W, pow_x);
  return !ebk.assertion_failed();
}

template <class Tweak>
[[gnu::noinline]]
bool tamper_rejected(const Field& F, const NativeWitness& nw,
                     const Elt pow_x[kBits128], Tweak tweak) {
  EvalBackend ebk(F,  false);
  EvalLogic L(&ebk, F);
  auto W = fill_eval_wires(L, F, nw);
  tweak(L, F, *W);
  assert_statement(L, F, *W, pow_x);
  return ebk.assertion_failed();
}

void test_circuit_constraints(const Field& F, Tally& t,
                              const NativeWitness& nw,
                              const Elt pow_x[kBits128]) {
  t.record("honest statement: all constraints satisfied",
           eval_validate(F, nw, pow_x));

  t.record("tamper r_bytes[0][0] → reveal-r SHA rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.commit.r_bytes[0][0][0].c0 = F.addf(W.commit.r_bytes[0][0][0].c0, F.one());
           }));

  t.record("tamper m̂[0] → HM affine line 0 rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.commit.mhat[0][0].c0 = F.addf(W.commit.mhat[0][0].c0, F.one());
           }));
  t.record("tamper m̂[16] → HM affine line 1 rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.commit.mhat[16][0].c0 = F.addf(W.commit.mhat[16][0].c0, F.one());
           }));

  t.record("tamper b_bytes[0][0] → HM affine/com-digest rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.commit.b_bytes[0][0][0].c0 = F.addf(W.commit.b_bytes[0][0][0].c0, F.one());
           }));
  t.record("tamper nonce[0] → message-hash SHA rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.nonce[0][0].c0 = F.addf(W.xmss.nonce[0][0].c0, F.one());
           }));

  t.record("tamper sig_hash[0] → WOTS+ chain rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.sig_hash[0][0].c0 = F.addf(W.xmss.sig_hash[0][0].c0, F.one());
           }));
  t.record("tamper sig_hash[0][160] → upper node limb rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.sig_hash[0][160].c0 =
                 F.addf(W.xmss.sig_hash[0][160].c0, F.one());
           }));

  t.record("tamper step chain h1[0] → pooled chain SHA rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic& L, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.step_bw[0][0].h1[0][0] =
                 L.add(W.xmss.step_bw[0][0].h1[0][0], L.konst(F.one()));
           }));
  t.record("tamper auth_path[0] → Merkle walk rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.auth[0][0].c0 = F.addf(W.xmss.auth[0][0].c0, F.one());
           }));

  t.record("tamper root[160] → upper node limb rejected",
           tamper_rejected(F, nw, pow_x, [](const EvalLogic&, const Field& F,
                                            StatementWires<EvalLogic>& W) {
             W.xmss.xmss_root[160].c0 =
                 F.addf(W.xmss.xmss_root[160].c0, F.one());
           }));
}

void test_protocol(Tally& t, const Field& F, const Circuit<Field>& circuit) {

  SignerKey key;
  DeterministicRng krng(0x516E27);
  krng.fill_bytes(key.sk_seed, kSkSeedBytes);
  krng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
  key.height = static_cast<uint8_t>(kTestXmssH);
  key.next_leaf = 0;
  const XmssKeyPair kp =
      XmssKeyPair::generate_from_seed(key.sk_seed, key.pk_seed, kTestXmssH);
  const Node xmss_root = kp.public_key();

  const Bytes message = str_bytes("my secret message");

  DeterministicRng urng(42);
  UserState state;
  const HmCommitment com = user_commit(F, urng, message, state);

  const auto xmss_sig = signer_sign(key, com);
  t.record("signer_sign produced a signature", xmss_sig.has_value());
  if (!xmss_sig.has_value()) return;
  t.record("signed root matches public key", xmss_sig->root == xmss_root);

  const BlindSignature bsig = user_prove(F, circuit, state, *xmss_sig);
  t.record("user_prove produced a proof", !bsig.proof.empty());
  t.record("retained opening verifies",
           verify_hm_opening(F, com, state.opening.msg, state.opening.r));

  t.record("full blind signature verifies",
           verify_blind_sig(F, circuit, xmss_root, key.pk_seed, bsig, message));

  {
    BlindSignature bad_nonce = bsig;
    bad_nonce.proof[0] ^= 0x01;
    t.record("tampered Fiat-Shamir session nonce rejected",
             !verify_blind_sig(F, circuit, xmss_root, key.pk_seed, bad_nonce,
                               message));
  }
  {
    BlindSignature truncated;
    truncated.proof.resize(kFsNonceBytes - 1);
    t.record("truncated Fiat-Shamir nonce rejected",
             !verify_blind_sig(F, circuit, xmss_root, key.pk_seed, truncated,
                               message));
  }

  proofs::set_log_level(proofs::ERROR);

  t.record("wrong message rejected",
           !verify_blind_sig(F, circuit, xmss_root, key.pk_seed, bsig,
                             str_bytes("a different message")));

  {
    Node wrong_root = xmss_root;
    wrong_root[0] ^= 0x01;
    t.record("wrong signer root rejected",
             !verify_blind_sig(F, circuit, wrong_root, key.pk_seed, bsig,
                               message));
  }
  {

    PkSeed wrong_seed = key.pk_seed;
    wrong_seed[0] ^= 0x01;
    t.record("wrong signer pk_seed rejected",
             !verify_blind_sig(F, circuit, xmss_root, wrong_seed, bsig,
                               message));
  }

  {
    auto bad = NativeWitness::build_from(F, state.opening.msg, com,
                                         state.opening, *xmss_sig);
    bad->r_bytes[0][0] ^= 1;
    t.record("tampered witness yields no proof",
             blind_prove(F, circuit, *bad).empty());
  }

  proofs::set_log_level(proofs::INFO);
}

int run() {
  proofs::set_log_level(proofs::INFO);
  const Field F;
  Tally t;

  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);

  std::printf("== native primitives ==\n");
  test_sha_and_codeword(t);
  test_wots(t);
  test_xmss(t);
  test_signer_end_to_end(F, t);

  std::printf("\n== commitment opening ==\n");
  test_commitment(F, t);

  std::printf("\n== serialization round-trips ==\n");
  test_serialization(F, t);

  std::printf("\n== circuit constraint validation ==\n");
  std::printf("  (building native witness: XMSS keygen + sign...)\n");
  const auto nw = NativeWitness::build(F,  0xB11Ad3);
  test_circuit_constraints(F, t, *nw, pow_x);

  std::printf("\n== protocol round-trip + tamper ==\n");
  std::printf("  (loading XMSS circuit from cache, else compiling ~300 SHA blocks)...\n");
  auto circuit = build_or_load_circuit(F, pow_x, default_circuit_cache_path());
  std::printf("  circuit: ninputs=%zu npub_in=%zu nlayers=%zu\n",
              circuit->ninputs, circuit->npub_in, circuit->nl);
  test_protocol(t, F, *circuit);

  std::printf("\nTest suite %s: %d passed, %d failed\n",
              t.fail == 0 ? "PASS" : "FAIL", t.pass, t.fail);
  return t.fail == 0 ? 0 : 1;
}

}
}

int main() { return blind_longfellow::run(); }
