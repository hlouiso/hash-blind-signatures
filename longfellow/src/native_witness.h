/* Native counterpart of StatementWires. m_hat, domain_param and xmss_root are
 * public; all commitment, WOTS+, and authentication-path fields are secret. */

#ifndef BLIND_LONGFELLOW_NATIVE_WITNESS_H_
#define BLIND_LONGFELLOW_NATIVE_WITNESS_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "circuits/sha/flatsha256_witness.h"

#include "circuit/blind_stmt.h"
#include "commitment.h"
#include "field.h"
#include "sha.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {

using NativeBW = proofs::FlatSHA256Witness::BlockWitness;

struct NativeWitness {

  uint8_t m_hat[kHashBytes];
  uint8_t domain_param[kDomainParamLen];
  Node    xmss_root;

  std::array<std::array<uint8_t, kFeBytes>, kNNonce> r_bytes;
  std::array<std::array<std::array<uint8_t, kFeBytes>, kNNonce>, kNLines> a_bytes;
  std::array<std::array<uint8_t, kFeBytes>, kNLines> b_bytes;
  Hash com_d;
  std::array<NativeBW, kRevealBlocks> reveal_bw;
  std::array<NativeBW, kComBlocks> com_bw;

  uint8_t nonce[kNonceLength];
  Hash    message_hash;
  std::array<NativeBW, kMsgBlocks> msg_bw;

  std::array<Node, kLen> sig_hashes;
  std::array<Node, kLen> pk_hashes;
  std::array<uint8_t, kLen> coords;
  std::array<Node, kPooledChainLen> step_in;
  std::array<Node, kPooledChainLen> step_out;
  std::array<uint8_t, kPooledChainLen> step_chain_idx;
  std::array<uint8_t, kPooledChainLen> step_count;
  std::array<uint8_t, kPooledChainLen> step_position;
  std::array<std::array<NativeBW, kChainBlocks>, kPooledChainLen> step_bw;

  Node leaf;
  std::array<NativeBW, kLtreeBlocks> leaf_bw;

  uint32_t leaf_index;
  std::array<Node, kXmssH> auth_path;
  std::array<Node, kXmssH> merkle_parents;
  std::array<std::array<NativeBW, kTreeBlocks>, kXmssH> merkle_bw;

  static std::unique_ptr<NativeWitness> build(const Field& F, uint64_t seed);

  static std::unique_ptr<NativeWitness> build_from(
      const Field& F, const Bytes& user_msg, const HmCommitment& com,
      const CommitmentOpening& opening, const XmssSignature& xmss_sig);
};

}

#endif
