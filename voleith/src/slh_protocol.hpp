#pragma once
// The blind signature with pure SLH-DSA-SHAKE (empty context) as the
// underlying signature, on SHAKE256 alone: the tagged HM commitment of
// native/slh_commit.h, a signature on its digest d, and a VOLEitH proof of
// slh_circuit.hpp. The XMSS protocol of protocol.hpp is untouched.
#include <memory>

#include "slh_proof.hpp"

namespace voleith {

struct SlhPublicKey {
  std::array<uint8_t, 16> pk_seed, pk_root;
};

// The FIPS 205 secret key: what the signer needs to rebuild its key.
struct SlhSecretKey {
  std::array<uint8_t, 16> sk_seed, sk_prf, pk_seed, pk_root;
  SlhPublicKey public_key() const { return {pk_seed, pk_root}; }
};

struct SlhUserState {
  std::array<uint8_t, 32> digest;  // m_hat
  std::array<uint8_t, 96> r;
  std::array<uint8_t, 256> commitment;  // a || b || y
};

class SlhSigner {
  std::unique_ptr<slh_key, decltype(&slh_key_free)> key_;
  const slh_params& p_;
  std::array<uint8_t, 16> sk_seed_, sk_prf_;
  SlhSigner(const slh_params& p, slh_key* key, const SlhSecretKey& sk);

 public:
  // Algorithm 18 from explicit seeds; key generation computes the top tree.
  SlhSigner(const slh_params& p, const uint8_t sk_seed[16],
            const uint8_t sk_prf[16], const uint8_t pk_seed[16]);
  // Rebuilds a stored key; throws std::invalid_argument unless it yields
  // the stored PK.root.
  SlhSigner(const slh_params& p, const SlhSecretKey& sk);
  static SlhSigner generate(const slh_params& p);
  // Resumes a stored key from top_cache() without key generation; nullopt
  // unless the levels form its top tree's upper part, rooted at sk.pk_root.
  static std::optional<SlhSigner> from_cache(const slh_params& p, const SlhSecretKey& sk,
                                             uint32_t first,
                                             std::span<const uint8_t> levels);
  // The stored levels of the top-layer tree, from height top_first() up.
  Bytes top_cache() const;
  uint32_t top_first() const;
  SlhPublicKey public_key() const;
  SlhSecretKey secret_key() const;
  const slh_key* key() const { return key_.get(); }
  // The signer's round: a hedged pure signature on d = H(TAG_DIGEST || com).
  Bytes sign(const std::array<uint8_t, 256>& com) const;
};

std::array<uint8_t, 32> slh_message_digest(std::span<const uint8_t> message);
SlhUserState slh_commit(std::span<const uint8_t> message);
// r || a || SIG; throws std::invalid_argument unless the signature verifies.
Bytes slh_primary_witness(const slh_params& p, const SlhUserState& state,
                          const SlhPublicKey& pk, std::span<const uint8_t> sig);
SlhStatement slh_statement(const SlhPublicKey& pk, const std::array<uint8_t, 32>& m_hat);
Bytes slh_unblind(const slh_params& p, const SlhUserState& state,
                  const SlhPublicKey& pk, std::span<const uint8_t> sig);
bool slh_verify_signature(const slh_params& p, const SlhPublicKey& pk,
                          std::span<const uint8_t> message,
                          std::span<const uint8_t> proof);

// Artefact files of the stateless scheme, framed as in protocol.cpp
// ("HBVO001" and a kind byte). The kinds are the lower-case letters of their
// stateful counterparts: 'k' secret key, 'p' public key, 'u' user state and
// 's' signer response. Keys and responses then name the parameter set in one
// byte; only SLH-DSA-SHAKE-128-24 has one. The commitment keeps kind 'C'.
// Decoders throw std::invalid_argument on anything else.
inline constexpr size_t kSlhArtifactHeader = 8;
// The kind byte of a framed artefact, or 0.
char artifact_kind(std::span<const uint8_t> data);
Bytes encode_slh(const slh_params& p, const SlhSecretKey& sk);
Bytes encode_slh(const slh_params& p, const SlhPublicKey& pk);
Bytes encode_slh(const SlhUserState& state);
Bytes encode_slh_response(const slh_params& p, std::span<const uint8_t> sig);
SlhSecretKey decode_slh_secret(const slh_params& p, std::span<const uint8_t> data);
SlhPublicKey decode_slh_public(const slh_params& p, std::span<const uint8_t> data);
SlhUserState decode_slh_state(std::span<const uint8_t> data);
Bytes decode_slh_response(const slh_params& p, std::span<const uint8_t> data);

}  // namespace voleith
