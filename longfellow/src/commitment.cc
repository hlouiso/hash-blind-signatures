#include "commitment.h"

#include <cstring>

#include "util/crypto.h"
#include "util/panic.h"

namespace blind_longfellow {

namespace {

Elt elt_of_bytes(const Field& F, const FeBytes& b) {
  auto e = F.of_bytes_field(b.data());
  proofs::check(e.has_value(), "of_bytes_field failed");
  return e.value();
}

Elt m_hat_half_of(const Field& F, const Hash& m_hat, size_t k) {
  FeBytes half;
  std::memcpy(half.data(), m_hat.data() + k * kFeBytes, kFeBytes);
  return elt_of_bytes(F, half);
}

}

Tag tag_block(const char* label) {
  const size_t n = std::strlen(label);
  proofs::check(n <= 48, "tag label too long");
  Tag t;
  t.fill(0xFF);
  std::memcpy(t.data(), label, n);
  return t;
}

Hash tagged(const Tag& tag, const uint8_t* data, size_t len) {
  proofs::SHA256 h;
  h.Update(tag.data(), tag.size());
  h.Update(data, len);
  Hash out;
  h.DigestData(out.data());
  return out;
}

Midstate tag_midstate(const Tag& tag) { return sha256_midstate(tag.data()); }

const Tag kXmssTagMessage = tag_block("blind-xmss/sha256/v1/message-hash");
const Tag kXmssTagNonce = tag_block("blind-xmss/sha256/v1/commitment-y");
const Tag kXmssTagDigest = tag_block("blind-xmss/sha256/v1/commitment-d");

Hash hm_message_hash(const Bytes& msg) {
  return tagged(kXmssTagMessage, msg.data(), msg.size());
}

Hash hm_nonce_hash(const std::array<FeBytes, kNNonce>& r) {
  uint8_t buf[kNNonce * kFeBytes];
  for (size_t i = 0; i < kNNonce; ++i)
    std::memcpy(buf + i * kFeBytes, r[i].data(), kFeBytes);
  return tagged(kXmssTagNonce, buf, sizeof(buf));
}

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r) {
  const Hash m_hat = hm_message_hash(msg);

  HmCommitment com;
  com.a = a;
  for (size_t k = 0; k < kNLines; ++k) {
    Elt sum = F.zero();
    for (size_t i = 0; i < kNNonce; ++i) {
      sum = F.addf(sum, F.mulf(elt_of_bytes(F, a[k][i]), elt_of_bytes(F, r[i])));
    }
    const Elt b_fe = F.addf(m_hat_half_of(F, m_hat, k), sum);
    F.to_bytes_field(com.b[k].data(), b_fe);
  }
  com.y = hm_nonce_hash(r);
  return com;
}

std::pair<HmCommitment, CommitmentOpening> sample_commitment(const Field& F,
                                                             Rng& rng,
                                                             const Bytes& msg) {
  std::array<std::array<FeBytes, kNNonce>, kNLines> a;
  std::array<FeBytes, kNNonce> r;
  for (size_t i = 0; i < kNNonce; ++i) rng.fill_bytes(r[i].data(), r[i].size());
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i)
      rng.fill_bytes(a[k][i].data(), a[k][i].size());
  HmCommitment com = hm_commit(F, msg, a, r);
  CommitmentOpening opening{msg, r};
  return {com, opening};
}

bool verify_hm_opening(const Field& F, const HmCommitment& com,
                       const Bytes& msg,
                       const std::array<FeBytes, kNNonce>& r) {
  if (hm_nonce_hash(r) != com.y) return false;

  const Hash m_hat = hm_message_hash(msg);
  for (size_t k = 0; k < kNLines; ++k) {
    Elt sum = F.zero();
    for (size_t i = 0; i < kNNonce; ++i) {
      sum = F.addf(sum,
                   F.mulf(elt_of_bytes(F, com.a[k][i]), elt_of_bytes(F, r[i])));
    }
    const Elt lhs = F.addf(elt_of_bytes(F, com.b[k]), sum);
    if (!(lhs == m_hat_half_of(F, m_hat, k))) return false;
  }
  return true;
}

Bytes hm_com_digest_preimage(const HmCommitment& com) {
  Bytes pre;
  pre.reserve(kComBytes);
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i)
      pre.insert(pre.end(), com.a[k][i].begin(), com.a[k][i].end());
  for (size_t k = 0; k < kNLines; ++k)
    pre.insert(pre.end(), com.b[k].begin(), com.b[k].end());
  pre.insert(pre.end(), com.y.begin(), com.y.end());
  proofs::check(pre.size() == kComBytes, "hm_com_digest_preimage size");
  return pre;
}

Hash hm_com_digest(const HmCommitment& com) {
  const Bytes pre = hm_com_digest_preimage(com);
  return tagged(kXmssTagDigest, pre.data(), pre.size());
}

}
