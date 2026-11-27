/* Checks the native XMSS of this port against the shared vectors of
 * ../test-vectors/xmss (written by binius64's xmss_kat): every hash, the key
 * derivation from a seed, verification, and the tagged commitment. Both
 * implementations define the same SHA-256 target-sum XMSS instance and the
 * same commitment. */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "commitment.h"
#include "field.h"
#include "sha.h"
#include "slh_vectors.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {
namespace {

using testvec::Json;
using testvec::unhex;
using testvec::unhex_array;

int failures = 0;

void record(const std::string& name, bool ok) {
  if (!ok) ++failures;
  std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
}

std::vector<Node> nodes(const Json& arr) {
  std::vector<Node> out;
  for (const Json& v : arr.arr) out.push_back(unhex_array<kNodeBytes>(v.str));
  return out;
}

void check_hashes(const Json& vectors) {
  size_t i = 0;
  for (const Json& v : vectors.arr) {
    const std::string tag = "hash vector " + std::to_string(i++) + ": ";
    const PkSeed pk_seed = unhex_array<kPkSeedBytes>(v["pk_seed"].str);
    const Bytes param = build_wots_domain_param(pk_seed);
    const uint32_t epoch = static_cast<uint32_t>(v["epoch"].num);

    const Node chain = hash_chain(param, epoch, unhex_array<kNodeBytes>(v["chain_input"].str),
                                  static_cast<uint64_t>(v["chain_index"].num),
                                  static_cast<uint64_t>(v["chain_position"].num));
    record(tag + "chain", chain == unhex_array<kNodeBytes>(v["chain_hash"].str));

    const Node leaf = hash_public_key(param, epoch, nodes(v["leaf_inputs"]));
    record(tag + "leaf", leaf == unhex_array<kNodeBytes>(v["leaf_hash"].str));

    const Node tree = hash_tree_node(param, unhex_array<kNodeBytes>(v["tree_left"].str),
                                     unhex_array<kNodeBytes>(v["tree_right"].str),
                                     static_cast<uint32_t>(v["tree_level"].num),
                                     static_cast<uint32_t>(v["tree_index"].num));
    record(tag + "tree", tree == unhex_array<kNodeBytes>(v["tree_hash"].str));

    const Midstate mid = tree_midstate(param);
    Bytes mid_bytes;
    for (uint32_t w : mid)
      for (int s = 24; s >= 0; s -= 8) mid_bytes.push_back(static_cast<uint8_t>(w >> s));
    record(tag + "tree midstate", mid_bytes == unhex(v["tree_midstate"].str));

    const Bytes nonce = unhex(v["nonce"].str);
    const Bytes msg = unhex(v["message"].str);
    const Hash mh = hash_message(param, epoch, nonce.data(), nonce.size(), msg.data(), msg.size());
    record(tag + "message", Bytes(mh.begin(), mh.end()) == unhex(v["message_hash"].str));
  }
}

void check_keys(const Json& keys) {
  const WinternitzSpec spec = xmss_wots_spec();
  for (const Json& k : keys.arr) {
    const size_t height = static_cast<size_t>(k["height"].num);
    const std::string tag = "key h=" + std::to_string(height) + ": ";
    const std::array<uint8_t, kSkSeedBytes> sk_seed =
        unhex_array<kSkSeedBytes>(k["sk_seed"].str);
    const PkSeed pk_seed = unhex_array<kPkSeedBytes>(k["pk_seed"].str);
    const Node root = unhex_array<kNodeBytes>(k["root"].str);

    const XmssKeyPair kp = XmssKeyPair::generate_from_seed(sk_seed.data(), pk_seed, height);
    record(tag + "the same seed gives the same root", kp.public_key() == root);

    for (const Json& s : k["signatures"].arr) {
      const uint32_t leaf = static_cast<uint32_t>(s["leaf_index"].num);
      const std::string stag = tag + "leaf " + std::to_string(leaf) + ": ";
      const Bytes msg = unhex(s["message"].str);
      const Bytes nonce = unhex(s["nonce"].str);
      const std::vector<Node> sig_hashes = nodes(s["sig_hashes"]);
      const std::vector<Node> path_nodes = nodes(s["auth_path"]);
      AuthPath path{};
      const bool shaped = path_nodes.size() == kXmssH && sig_hashes.size() == kLen;
      record(stag + "24-node path and 42 chain values", shaped);
      if (!shaped) continue;
      std::copy(path_nodes.begin(), path_nodes.end(), path.begin());

      record(stag + "verifies", xmss_verify(spec, pk_seed, root, height, leaf, msg.data(),
                                            msg.size(), nonce, sig_hashes, path));
      Bytes other = msg;
      other[0] ^= 1;
      record(stag + "another message does not verify",
             !xmss_verify(spec, pk_seed, root, height, leaf, other.data(), other.size(), nonce,
                          sig_hashes, path));

      // The chain values are the chain starts walked to the digits, so the
      // key derivation agrees too.
      bool leftover_ok = false;
      const Hash mh = hash_message(build_wots_domain_param(pk_seed), leaf, nonce.data(),
                                   nonce.size(), msg.data(), msg.size());
      const std::vector<uint8_t> coords = extract_coords(mh.data(), &leftover_ok);
      const std::vector<Node> expected = compute_wots_signature(
          build_wots_domain_param(pk_seed), leaf, kp.wots_secret_key(leaf), coords);
      record(stag + "chain values from the derived key", leftover_ok && expected == sig_hashes);
    }
  }
}

void check_commitment(const Json& c) {
  const Field F;
  record("commitment tags match binius64",
         unhex(c["tag_message"].str) == Bytes(kXmssTagMessage.begin(), kXmssTagMessage.end()) &&
             unhex(c["tag_nonce"].str) == Bytes(kXmssTagNonce.begin(), kXmssTagNonce.end()) &&
             unhex(c["tag_digest"].str) == Bytes(kXmssTagDigest.begin(), kXmssTagDigest.end()));
  // Byte 16 holds the tweak (0..3) of every XMSS hash input, bytes 48..64 of
  // an HMAC block are 0x36 or 0x5c, and the transcript starts with 0x00.
  bool apart = kXmssTagMessage != kXmssTagNonce && kXmssTagNonce != kXmssTagDigest &&
               kXmssTagMessage != kXmssTagDigest;
  for (const Tag* t : {&kXmssTagMessage, &kXmssTagNonce, &kXmssTagDigest}) {
    apart &= (*t)[0] == 'b' && (*t)[16] > 3;
    for (size_t i = 48; i < kTagBytes; ++i) apart &= (*t)[i] == 0xFF;
  }
  record("commitment tags are apart from the other SHA-256 inputs", apart);
  size_t n = 0;
  for (const Json& v : c["vectors"].arr) {
    const std::string tag = "commitment vector " + std::to_string(n++) + ": ";
    const Bytes msg = unhex(v["msg"].str);
    const Bytes a_raw = unhex(v["a"].str), r_raw = unhex(v["r"].str);
    std::array<std::array<FeBytes, kNNonce>, kNLines> a;
    std::array<FeBytes, kNNonce> r;
    for (size_t k = 0; k < kNLines; ++k)
      for (size_t i = 0; i < kNNonce; ++i)
        std::memcpy(a[k][i].data(), &a_raw[(k * kNNonce + i) * kFeBytes], kFeBytes);
    for (size_t i = 0; i < kNNonce; ++i) std::memcpy(r[i].data(), &r_raw[i * kFeBytes], kFeBytes);
    const HmCommitment com = hm_commit(F, msg, a, r);
    const Hash mh = hm_message_hash(msg);
    const Hash d = hm_com_digest(com);
    Bytes b;
    for (const auto& bk : com.b) b.insert(b.end(), bk.begin(), bk.end());
    record(tag + "m_hat, b, y, encoding and d match",
           Bytes(mh.begin(), mh.end()) == unhex(v["m_hat"].str) && b == unhex(v["b"].str) &&
               Bytes(com.y.begin(), com.y.end()) == unhex(v["y"].str) &&
               hm_com_digest_preimage(com) == unhex(v["commitment"].str) &&
               Bytes(d.begin(), d.end()) == unhex(v["d"].str));
    auto bad = r;
    bad[5][15] ^= 1;
    record(tag + "opening verifies, a wrong r does not",
           verify_hm_opening(F, com, msg, r) && !verify_hm_opening(F, com, msg, bad));
  }
}

}  // namespace
}  // namespace blind_longfellow

int main() {
  using namespace blind_longfellow;
  const testvec::Json v =
      testvec::load_json(std::string(XMSS_TEST_VECTOR_DIR) + "/sha256-xmss.json");
  record("vectors are for a 24-level path",
         static_cast<size_t>(v["log_lifetime"].num) == kXmssH);
  check_hashes(v["hashes"]);
  check_keys(v["keys"]);
  check_commitment(v["commitment"]);
  std::printf("%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
  return failures ? 1 : 0;
}
