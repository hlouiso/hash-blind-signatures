#include "native_witness.h"

#include <cstring>
#include <vector>

#include "circuits/sha/flatsha256_witness.h"
#include "util/log.h"
#include "util/panic.h"

#include "commitment.h"
#include "rng.h"
#include "sha.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {
namespace {

[[gnu::noinline]]
static void fill_parts(NativeWitness& w, const Field& F,
                       const Bytes& user_msg,
                       const HmCommitment& com,
                       const CommitmentOpening& opening,
                       const XmssSignature& sig) {
  const Bytes& dp = sig.wots.domain_param;
  proofs::check(dp.size() == kDomainParamLen, "fill_parts: domain_param size");
  proofs::check(sig.wots.sig_hashes.size() == kLen, "sig_hashes size");
  proofs::check(sig.wots.pk_hashes.size() == kLen, "pk_hashes size");
  proofs::check(sig.wots.coords.size() == kLen, "coords size");
  proofs::check(sig.xmss_calls.size() == kXmssH, "xmss_calls size");

  const Hash m_hat = sha256(user_msg);
  std::memcpy(w.m_hat, m_hat.data(), kHashBytes);

  for (size_t i = 0; i < kNNonce; ++i) {
    std::memcpy(w.r_bytes[i].data(), opening.r[i].data(), kFeBytes);
  }
  for (size_t k = 0; k < kNLines; ++k) {
    for (size_t i = 0; i < kNNonce; ++i)
      std::memcpy(w.a_bytes[k][i].data(), com.a[k][i].data(), kFeBytes);
    std::memcpy(w.b_bytes[k].data(), com.b[k].data(), kFeBytes);
  }
  w.com_d = hm_com_digest(com);
  std::memcpy(w.domain_param, dp.data(), kDomainParamLen);
  w.xmss_root = sig.root;

  std::memcpy(w.nonce, sig.wots.nonce.data(), kNonceLength);
  w.message_hash = sig.wots.message_hash;
  for (size_t i = 0; i < kLen; ++i) {
    w.sig_hashes[i] = sig.wots.sig_hashes[i];
    w.pk_hashes[i]  = sig.wots.pk_hashes[i];
    w.coords[i]     = sig.wots.coords[i];
  }
  w.leaf       = sig.leaf;
  w.leaf_index = sig.leaf_index;
  for (size_t h = 0; h < kXmssH; ++h) {
    w.auth_path[h]      = sig.auth_path[h];
    w.merkle_parents[h] = sig.xmss_calls[h].output;
  }

  {
    uint8_t pre[kRevealLen];
    for (size_t i = 0; i < kNNonce; ++i)
      std::memcpy(pre + i * kFeBytes, w.r_bytes[i].data(), kFeBytes);
    uint8_t numb = 0;
    uint8_t pad[64 * kRevealBlocks];
    proofs::FlatSHA256Witness::transform_and_witness_message(
        kRevealLen, pre, kRevealBlocks, numb, pad, w.reveal_bw.data());
    proofs::check(numb == kRevealBlocks, "reveal-r block count");
  }

  {
    const Bytes pre = hm_com_digest_preimage(com);
    uint8_t numb = 0;
    std::vector<uint8_t> pad(64 * kComBlocks);
    proofs::FlatSHA256Witness::transform_and_witness_message(
        kComLen, pre.data(), kComBlocks, numb, pad.data(), w.com_bw.data());
    proofs::check(numb == kComBlocks, "com-digest block count");
  }

  {
    const Bytes pre = build_message_hash(dp, w.leaf_index, w.nonce, kNonceLength,
                                         w.com_d.data(), kHashBytes);
    uint8_t numb = 0;
    uint8_t pad[64 * kMsgBlocks];
    proofs::FlatSHA256Witness::transform_and_witness_message(
        kMsgLen, pre.data(), kMsgBlocks, numb, pad, w.msg_bw.data());
    proofs::check(numb == kMsgBlocks, "msg block count");
  }

  {
    size_t slot = 0;
    for (size_t i = 0; i < kLen; ++i) {
      Node current = w.sig_hashes[i];
      const size_t remaining = (kW - 1) - static_cast<size_t>(w.coords[i]);
      for (size_t step = 0; step < remaining; ++step) {
        const uint64_t pos = static_cast<uint64_t>(w.coords[i]) + step + 1;
        const Bytes pre = build_chain_hash(dp, w.leaf_index, current, i, pos);
        w.step_in[slot] = current;
        w.step_out[slot] = sha256_node(pre);
        w.step_chain_idx[slot] = static_cast<uint8_t>(i);
        w.step_count[slot] = static_cast<uint8_t>(step + 1);
        w.step_position[slot] = static_cast<uint8_t>(pos);
        uint8_t numb = 0;
        uint8_t pad[64 * kChainBlocks];
        proofs::FlatSHA256Witness::transform_and_witness_message(
            kChainLen, pre.data(), kChainBlocks, numb, pad,
            w.step_bw[slot].data());
        proofs::check(numb == kChainBlocks, "chain block count");
        current = w.step_out[slot];
        ++slot;
      }
      proofs::check(current == w.pk_hashes[i], "pooled chain endpoint != pk");
    }
    proofs::check(slot == kPooledChainLen, "pooled chain slot count");
  }

  {
    const std::vector<Node> pk_vec(w.pk_hashes.begin(), w.pk_hashes.end());
    const Bytes pre = build_public_key_hash(dp, w.leaf_index, pk_vec);
    uint8_t numb = 0;
    std::vector<uint8_t> pad(64 * kLtreeBlocks);
    proofs::FlatSHA256Witness::transform_and_witness_message(
        kLtreeLen, pre.data(), kLtreeBlocks, numb, pad.data(),
        w.leaf_bw.data());
    proofs::check(numb == kLtreeBlocks, "ltree block count");
  }

  const Midstate mid = tree_midstate(dp);
  for (size_t h = 0; h < kXmssH; ++h) {
    const auto& tc = sig.xmss_calls[h];

    const uint32_t node_idx =
        static_cast<uint32_t>(static_cast<uint64_t>(w.leaf_index) >> (h + 1));
    const Bytes pre = build_tree_hash(dp, tc.left, tc.right,
                                      static_cast<uint32_t>(h), node_idx);
    proofs::check(pre.size() == kTreeLen, "merkle preimage length");
    proofs::check(sha256_node(pre) == tc.output, "merkle parent != tree hash");

    uint8_t block[64] = {};
    std::memcpy(block, pre.data() + kTreePrefixBytes, kTreeTailLen);
    block[kTreeTailLen] = 0x80;
    const uint64_t bitlen = static_cast<uint64_t>(kTreeLen) * 8;
    for (size_t k = 0; k < 8; ++k)
      block[63 - k] = static_cast<uint8_t>((bitlen >> (8 * k)) & 0xff);

    uint32_t in[16];
    for (size_t i = 0; i < 16; ++i)
      in[i] = proofs::SHA256_ru32be(block + 4 * i);
    NativeBW& bw = w.merkle_bw[h][0];
    proofs::FlatSHA256Witness::transform_and_witness_block(
        in, mid.data(), bw.outw, bw.oute, bw.outa, bw.h1);
  }
}

}

std::unique_ptr<NativeWitness> NativeWitness::build(const Field& F,
                                                     uint64_t seed) {
  DeterministicRng rng(seed);
  const WinternitzSpec spec = xmss_wots_spec();

  PkSeed pk_seed;
  rng.fill_bytes(pk_seed.data(), pk_seed.size());
  XmssKeyPair kp = XmssKeyPair::generate(rng, pk_seed);

  const uint8_t raw[] = {'b','l','i','n','d','-','l','o','n','g','f','e','l',
                         'l','o','w',' ','t','e','s','t'};
  const Bytes user_msg(raw, raw + sizeof(raw));
  auto [com, opening] = sample_commitment(F, rng, user_msg);

  const Hash d = hm_com_digest(com);
  auto sig = kp.sign(spec, rng, d.data(), d.size());
  proofs::check(sig.has_value(), "NativeWitness::build: signing failed");

  auto wp = std::make_unique<NativeWitness>();
  fill_parts(*wp, F, user_msg, com, opening, *sig);
  return wp;
}

std::unique_ptr<NativeWitness> NativeWitness::build_from(
    const Field& F, const Bytes& user_msg, const HmCommitment& com,
    const CommitmentOpening& opening, const XmssSignature& xmss_sig) {
  auto wp = std::make_unique<NativeWitness>();
  fill_parts(*wp, F, user_msg, com, opening, xmss_sig);
  return wp;
}

}
