#include "commitment.h"

#include <cstring>

#include "util/panic.h"

namespace blind_longfellow {

namespace {

Elt elt_of_bytes(const Field& F, const FeBytes& b) {
  auto e = F.of_bytes_field(b.data());
  proofs::check(e.has_value(), "of_bytes_field failed");
  return e.value();
}

Hash hash_r(const std::array<FeBytes, kNNonce>& r) {
  proofs::SHA256 h;
  for (const FeBytes& r_i : r) h.Update(r_i.data(), r_i.size());
  Hash out;
  h.DigestData(out.data());
  return out;
}

Elt m_hat_half_of(const Field& F, const Hash& m_hat, size_t k) {
  FeBytes half;
  std::memcpy(half.data(), m_hat.data() + k * kFeBytes, kFeBytes);
  return elt_of_bytes(F, half);
}

}

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r) {
  const Hash m_hat = sha256(msg);

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
  com.y = hash_r(r);
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
  if (hash_r(r) != com.y) return false;

  const Hash m_hat = sha256(msg);
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
  return sha256(hm_com_digest_preimage(com));
}

}
