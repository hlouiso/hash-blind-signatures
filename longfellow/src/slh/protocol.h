/* The blind signature with pure SLH-DSA-SHA2 (empty context) as the
 * underlying signature, on SHA-256 alone. The user commits to the document
 * with the tagged Halevi–Micali commitment of slh/commit.h, the signer signs
 * the 32-byte digest d, and the blind signature is a Longfellow proof of
 * circuit/slh_stmt.h. The XMSS protocol of protocol.h is untouched. */

#ifndef BLIND_LONGFELLOW_SLH_PROTOCOL_H_
#define BLIND_LONGFELLOW_SLH_PROTOCOL_H_

#include <array>
#include <cstdint>
#include <vector>

#include "commitment.h"
#include "field.h"
#include "rng.h"
#include "slh/native.h"
#include "slh/prover.h"

namespace blind_longfellow {
namespace slh {

struct SlhUserState {
  Bytes msg;
  HmCommitment com;
  CommitmentOpening opening;
};

struct SlhPublicKey {
  Node pk_seed, pk_root;
};

HmCommitment slh_user_commit(const Field& F, Rng& rng, const Bytes& msg,
                             SlhUserState& state);

// The signer's round: a hedged pure SLH-DSA signature on d.
SlhSignature slh_signer_sign(const SlhKey& key, const HmCommitment& com,
                             Rng& rng);

// The user's final round, witness generation included. Empty if the
// signature does not verify.
std::vector<uint8_t> slh_user_prove(const Field& F, const SlhParams& p,
                                    const proofs::Circuit<Field>& circuit,
                                    const SlhUserState& state,
                                    const SlhPublicKey& pk,
                                    const SlhSignature& sig);

bool slh_verify_blind(const Field& F, const SlhParams& p,
                      const proofs::Circuit<Field>& circuit,
                      const SlhPublicKey& pk, const std::vector<uint8_t>& proof,
                      const Bytes& msg);

// File encodings of the stateless scheme, for the CLI. Each starts with an
// 8-byte magic, which the stateful (XMSS) encodings of protocol.h lack, and
// key and signature files then name the parameter set in one byte:
//   signer key: "HBS-SLHK" || set || SK.seed || SK.prf || PK.seed || PK.root
//   public key: "HBS-SLHP" || set || PK.seed || PK.root
//   signature:  "HBS-SLHS" || set || the FIPS 205 encoding
//   user state: "HBS-SLHU" || the user-state encoding of protocol.h
// The readers throw std::runtime_error on anything else.
using Magic = std::array<uint8_t, 8>;
extern const Magic kSlhKeyMagic, kSlhPubMagic, kSlhSigMagic, kSlhStateMagic;
bool has_magic(const std::vector<uint8_t>& buf, const Magic& magic);

// The FIPS 205 secret key: what the signer needs to rebuild its key.
struct SlhSecretKey {
  Node sk_seed, sk_prf, pk_seed, pk_root;
  SlhPublicKey public_key() const { return {pk_seed, pk_root}; }
};

std::vector<uint8_t> write_slh_key(const SlhParams& p, const SlhSecretKey& key);
SlhSecretKey read_slh_key(const std::vector<uint8_t>& buf, SlhParams* p);
std::vector<uint8_t> write_slh_pub(const SlhParams& p, const SlhPublicKey& pk);
SlhPublicKey read_slh_pub(const std::vector<uint8_t>& buf, SlhParams* p);
std::vector<uint8_t> write_slh_sig(const SlhParams& p, const SlhSignature& sig);
SlhSignature read_slh_sig(const std::vector<uint8_t>& buf, const SlhParams& p);
std::vector<uint8_t> write_slh_user_state(const SlhUserState& state);
SlhUserState read_slh_user_state(const std::vector<uint8_t>& buf);

}  // namespace slh
}  // namespace blind_longfellow

#endif
