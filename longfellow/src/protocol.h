/* The proof establishes a commitment opening for m_hat and an XMSS signature
 * on its digest. pk_seed, root and the real height are authenticated external
 * inputs; the commitment and leaf index are not part of the blind signature. */

#ifndef BLIND_LONGFELLOW_PROTOCOL_H_
#define BLIND_LONGFELLOW_PROTOCOL_H_

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "arrays/dense.h"
#include "zk/zk_proof.h"

#include "commitment.h"
#include "field.h"
#include "native_witness.h"
#include "prover.h"
#include "sha.h"
#include "verifier.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {

struct SignerKey {
  uint8_t sk_seed[kSkSeedBytes];
  PkSeed  pk_seed;

  uint8_t height = static_cast<uint8_t>(kXmssH);
  uint64_t next_leaf;
};

struct UserState {
  Bytes msg;
  HmCommitment com;
  CommitmentOpening opening;
};

struct BlindSignature {
  std::vector<uint8_t> proof;
};

struct SignerPub {
  Node root;
  PkSeed pk_seed;
  uint8_t height;
};

HmCommitment user_commit(const Field& F, Rng& rng, const Bytes& msg,
                          UserState& out_state);

std::optional<XmssSignature> signer_sign(SignerKey& key,
                                          const HmCommitment& com);

// As signer_sign, with the key's tree already built (for instance resumed
// from XmssKeyPair::from_top_levels). nullopt if the key is exhausted or kp
// is not the tree of `key`; key.next_leaf advances only on success.
std::optional<XmssSignature> signer_sign_with(XmssKeyPair& kp, SignerKey& key,
                                              const HmCommitment& com);

BlindSignature user_prove(const Field& F,
                           const proofs::Circuit<Field>& circuit,
                           const UserState& state,
                           const XmssSignature& xmss_sig);

bool verify_blind_sig(const Field& F, const proofs::Circuit<Field>& circuit,
                      const SignerPub& pub, const BlindSignature& sig,
                      const Bytes& msg);

std::vector<uint8_t> write_signer_key(const SignerKey& key);
SignerKey read_signer_key(const std::vector<uint8_t>& buf);

std::vector<uint8_t> write_signer_pub(const SignerPub& pub);
SignerPub read_signer_pub(const std::vector<uint8_t>& buf);

std::vector<uint8_t> write_commitment(const HmCommitment& com);
HmCommitment read_commitment(const std::vector<uint8_t>& buf);

std::vector<uint8_t> write_user_state(const UserState& state);
UserState read_user_state(const std::vector<uint8_t>& buf);

std::vector<uint8_t> write_xmss_sig(const XmssSignature& sig);
std::optional<XmssSignature> read_xmss_sig(const std::vector<uint8_t>& buf,
                                           const PkSeed& pk_seed, size_t height,
                                           const uint8_t* message,
                                           size_t message_len);

std::vector<uint8_t> write_blind_sig(const BlindSignature& sig);
BlindSignature read_blind_sig(const std::vector<uint8_t>& buf);

}

#endif
