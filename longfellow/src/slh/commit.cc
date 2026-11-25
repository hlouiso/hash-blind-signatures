#include "slh/commit.h"

#include <cstring>

#include "util/crypto.h"
#include "util/panic.h"

namespace blind_longfellow {
namespace slh {
namespace {

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

Elt elt_of_bytes(const Field& F, const FeBytes& b) {
  auto e = F.of_bytes_field(b.data());
  proofs::check(e.has_value(), "of_bytes_field failed");
  return e.value();
}

Elt half(const Field& F, const Hash& h, size_t k) {
  FeBytes x;
  std::memcpy(x.data(), h.data() + k * kFeBytes, kFeBytes);
  return elt_of_bytes(F, x);
}

Elt line_sum(const Field& F, const std::array<FeBytes, kNNonce>& a_k,
             const std::array<FeBytes, kNNonce>& r) {
  Elt sum = F.zero();
  for (size_t i = 0; i < kNNonce; ++i)
    sum = F.addf(sum, F.mulf(elt_of_bytes(F, a_k[i]), elt_of_bytes(F, r[i])));
  return sum;
}

}  // namespace

const Tag kTagMessage = tag_block("blind-slh-dsa/sha256/v1/message-hash");
const Tag kTagNonce = tag_block("blind-slh-dsa/sha256/v1/commitment-y");
const Tag kTagDigest = tag_block("blind-slh-dsa/sha256/v1/commitment-d");

State tag_midstate(const Tag& tag) { return sha256_block_midstate(tag.data()); }

Hash message_hash(const uint8_t* msg, size_t len) {
  return tagged(kTagMessage, msg, len);
}

Hash nonce_hash(const std::array<FeBytes, kNNonce>& r) {
  uint8_t buf[kNNonce * kFeBytes];
  for (size_t i = 0; i < kNNonce; ++i)
    std::memcpy(buf + i * kFeBytes, r[i].data(), kFeBytes);
  return tagged(kTagNonce, buf, sizeof(buf));
}

Hash com_digest(const HmCommitment& com) {
  const Bytes pre = hm_com_digest_preimage(com);
  return tagged(kTagDigest, pre.data(), pre.size());
}

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r) {
  const Hash m_hat = message_hash(msg);
  HmCommitment com;
  com.a = a;
  for (size_t k = 0; k < kNLines; ++k)
    F.to_bytes_field(com.b[k].data(),
                     F.addf(half(F, m_hat, k), line_sum(F, a[k], r)));
  com.y = nonce_hash(r);
  return com;
}

std::pair<HmCommitment, CommitmentOpening> sample_commitment(const Field& F,
                                                             Rng& rng,
                                                             const Bytes& msg) {
  std::array<std::array<FeBytes, kNNonce>, kNLines> a;
  std::array<FeBytes, kNNonce> r;
  for (auto& r_i : r) rng.fill_bytes(r_i.data(), r_i.size());
  for (auto& line : a)
    for (auto& a_i : line) rng.fill_bytes(a_i.data(), a_i.size());
  return {slh::hm_commit(F, msg, a, r), CommitmentOpening{msg, r}};
}

bool verify_opening(const Field& F, const HmCommitment& com, const Bytes& msg,
                    const std::array<FeBytes, kNNonce>& r) {
  if (nonce_hash(r) != com.y) return false;
  const Hash m_hat = message_hash(msg);
  for (size_t k = 0; k < kNLines; ++k) {
    const Elt lhs = F.addf(elt_of_bytes(F, com.b[k]), line_sum(F, com.a[k], r));
    if (!(lhs == half(F, m_hat, k))) return false;
  }
  return true;
}

}  // namespace slh
}  // namespace blind_longfellow
