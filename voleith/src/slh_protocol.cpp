#include "slh_protocol.hpp"

#include <cstring>
#include <string>
#include <string_view>
extern "C" {
#include "native/randombytes.h"
}

namespace voleith {
namespace {
void random(std::span<uint8_t> out) {
  if (!randombytes_fill(out.data(), out.size()))
    throw std::runtime_error("OS random source failed");
}
}  // namespace

SlhSigner::SlhSigner(const slh_params& p, const uint8_t sk_seed[16],
                     const uint8_t sk_prf[16], const uint8_t pk_seed[16])
    : key_(slh_keygen_internal(&p, sk_seed, sk_prf, pk_seed), slh_key_free), p_(p) {
  if (!key_) throw std::runtime_error("SLH-DSA key generation failed");
  memcpy(sk_seed_.data(), sk_seed, 16);
  memcpy(sk_prf_.data(), sk_prf, 16);
}

SlhSigner::SlhSigner(const slh_params& p, const SlhSecretKey& sk)
    : SlhSigner(p, sk.sk_seed.data(), sk.sk_prf.data(), sk.pk_seed.data()) {
  if (public_key().pk_root != sk.pk_root)
    throw std::invalid_argument("SLH-DSA secret key does not yield its PK.root");
}

SlhSigner::SlhSigner(const slh_params& p, slh_key* key, const SlhSecretKey& sk)
    : key_(key, slh_key_free), p_(p), sk_seed_(sk.sk_seed), sk_prf_(sk.sk_prf) {}

std::optional<SlhSigner> SlhSigner::from_cache(const slh_params& p, const SlhSecretKey& sk,
                                               uint32_t first,
                                               std::span<const uint8_t> levels) {
  slh_key* key = slh_key_from_top(&p, sk.sk_seed.data(), sk.sk_prf.data(), sk.pk_seed.data(),
                                  sk.pk_root.data(), first, levels.data(), levels.size());
  if (!key) return std::nullopt;
  return SlhSigner(p, key, sk);
}

Bytes SlhSigner::top_cache() const {
  Bytes out(slh_key_top_bytes(key_.get()));
  slh_key_export_top(key_.get(), out.data());
  return out;
}

uint32_t SlhSigner::top_first() const { return slh_key_top_first(key_.get()); }

SlhSecretKey SlhSigner::secret_key() const {
  const SlhPublicKey pk = public_key();
  return {sk_seed_, sk_prf_, pk.pk_seed, pk.pk_root};
}

SlhSigner SlhSigner::generate(const slh_params& p) {
  std::array<uint8_t, 48> seeds;
  random(seeds);
  return SlhSigner(p, seeds.data(), seeds.data() + 16, seeds.data() + 32);
}

SlhPublicKey SlhSigner::public_key() const {
  SlhPublicKey pk;
  slh_key_pk_seed(key_.get(), pk.pk_seed.data());
  slh_key_pk_root(key_.get(), pk.pk_root.data());
  return pk;
}

Bytes SlhSigner::sign(const std::array<uint8_t, 256>& com) const {
  std::array<uint8_t, 32> d;
  slh_com_digest(com.data(), d.data());
  std::array<uint8_t, 16> addrnd;
  random(addrnd);
  Bytes sig(slh_sig_bytes(&p_));
  slh_sign(key_.get(), d.data(), d.size(), addrnd.data(), sig.data());
  return sig;
}

std::array<uint8_t, 32> slh_message_digest(std::span<const uint8_t> message) {
  std::array<uint8_t, 32> m_hat;
  slh_message_hash(message.data(), message.size(), m_hat.data());
  return m_hat;
}

SlhUserState slh_commit(std::span<const uint8_t> message) {
  SlhUserState s{};
  s.digest = slh_message_digest(message);
  random(s.r);
  std::array<uint8_t, HM_A_BYTES> a;
  random(a);
  std::array<uint8_t, 32> d;
  slh_hm_commit(s.digest.data(), s.r.data(), a.data(), s.commitment.data(), d.data());
  return s;
}

SlhStatement slh_statement(const SlhPublicKey& pk, const std::array<uint8_t, 32>& m_hat) {
  return {m_hat, pk.pk_seed, pk.pk_root};
}

Bytes slh_primary_witness(const slh_params& p, const SlhUserState& state,
                          const SlhPublicKey& pk, std::span<const uint8_t> sig) {
  std::array<uint8_t, HM_COM_BYTES> com;
  std::array<uint8_t, 32> d;
  slh_hm_commit(state.digest.data(), state.r.data(), state.commitment.data(), com.data(),
                d.data());
  if (com != state.commitment) throw std::invalid_argument("inconsistent HM opening");
  if (!slh_verify(&p, pk.pk_seed.data(), pk.pk_root.data(), d.data(), d.size(),
                  sig.data(), sig.size()))
    throw std::invalid_argument("invalid SLH-DSA signer response");
  Bytes primary(HM_R_BYTES + HM_A_BYTES + sig.size());
  memcpy(primary.data(), state.r.data(), HM_R_BYTES);
  memcpy(primary.data() + HM_R_BYTES, state.commitment.data(), HM_A_BYTES);
  memcpy(primary.data() + HM_R_BYTES + HM_A_BYTES, sig.data(), sig.size());
  return primary;
}

Bytes slh_unblind(const slh_params& p, const SlhUserState& state,
                  const SlhPublicKey& pk, std::span<const uint8_t> sig) {
  return prove_slh(p, slh_statement(pk, state.digest),
                   slh_primary_witness(p, state, pk, sig));
}

bool slh_verify_signature(const slh_params& p, const SlhPublicKey& pk,
                          std::span<const uint8_t> message,
                          std::span<const uint8_t> proof) {
  return verify_slh(p, slh_statement(pk, slh_message_digest(message)), proof);
}

namespace {
constexpr char kMagic[] = "HBVO001";  // as protocol.cpp
constexpr uint8_t kSet128_24 = 1;

uint8_t set_id(const slh_params& p) {
  if (std::string_view(p.name) != kSlhShake128_24.name)
    throw std::invalid_argument(std::string("no artefact identifier for ") + p.name);
  return kSet128_24;
}

// kind, then the set byte if `keyed`, then n payload bytes.
Bytes slh_frame(char kind, const slh_params* p, size_t n) {
  Bytes b(kSlhArtifactHeader + (p ? 1 : 0) + n);
  memcpy(b.data(), kMagic, 7);
  b[7] = static_cast<uint8_t>(kind);
  if (p) b[8] = set_id(*p);
  return b;
}

const uint8_t* slh_payload(std::span<const uint8_t> b, char kind, const slh_params* p,
                           size_t n) {
  const size_t head = kSlhArtifactHeader + (p ? 1 : 0);
  if (b.size() != head + n || artifact_kind(b) != kind || (p && b[8] != set_id(*p)))
    throw std::invalid_argument("wrong artifact type, version, parameter set or length");
  return b.data() + head;
}
}  // namespace

char artifact_kind(std::span<const uint8_t> b) {
  if (b.size() < kSlhArtifactHeader || memcmp(b.data(), kMagic, 7) != 0) return 0;
  return static_cast<char>(b[7]);
}

Bytes encode_slh(const slh_params& p, const SlhSecretKey& sk) {
  auto b = slh_frame('k', &p, 64);
  auto q = b.data() + kSlhArtifactHeader + 1;
  for (const auto* n : {&sk.sk_seed, &sk.sk_prf, &sk.pk_seed, &sk.pk_root}) {
    memcpy(q, n->data(), 16);
    q += 16;
  }
  return b;
}

SlhSecretKey decode_slh_secret(const slh_params& p, std::span<const uint8_t> b) {
  auto q = slh_payload(b, 'k', &p, 64);
  SlhSecretKey sk;
  for (auto* n : {&sk.sk_seed, &sk.sk_prf, &sk.pk_seed, &sk.pk_root}) {
    memcpy(n->data(), q, 16);
    q += 16;
  }
  return sk;
}

Bytes encode_slh(const slh_params& p, const SlhPublicKey& pk) {
  auto b = slh_frame('p', &p, 32);
  memcpy(b.data() + kSlhArtifactHeader + 1, pk.pk_seed.data(), 16);
  memcpy(b.data() + kSlhArtifactHeader + 17, pk.pk_root.data(), 16);
  return b;
}

SlhPublicKey decode_slh_public(const slh_params& p, std::span<const uint8_t> b) {
  auto q = slh_payload(b, 'p', &p, 32);
  SlhPublicKey pk;
  memcpy(pk.pk_seed.data(), q, 16);
  memcpy(pk.pk_root.data(), q + 16, 16);
  return pk;
}

Bytes encode_slh(const SlhUserState& s) {
  auto b = slh_frame('u', nullptr, 384);
  auto q = b.data() + kSlhArtifactHeader;
  memcpy(q, s.digest.data(), 32);
  memcpy(q + 32, s.r.data(), 96);
  memcpy(q + 128, s.commitment.data(), 256);
  return b;
}

SlhUserState decode_slh_state(std::span<const uint8_t> b) {
  auto q = slh_payload(b, 'u', nullptr, 384);
  SlhUserState s;
  memcpy(s.digest.data(), q, 32);
  memcpy(s.r.data(), q + 32, 96);
  memcpy(s.commitment.data(), q + 128, 256);
  return s;
}

Bytes encode_slh_response(const slh_params& p, std::span<const uint8_t> sig) {
  if (sig.size() != slh_sig_bytes(&p)) throw std::invalid_argument("SLH-DSA signature length");
  auto b = slh_frame('s', &p, sig.size());
  memcpy(b.data() + kSlhArtifactHeader + 1, sig.data(), sig.size());
  return b;
}

Bytes decode_slh_response(const slh_params& p, std::span<const uint8_t> b) {
  auto q = slh_payload(b, 's', &p, slh_sig_bytes(&p));
  return Bytes(q, q + slh_sig_bytes(&p));
}

}  // namespace voleith
