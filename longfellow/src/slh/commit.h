/* The Halevi–Micali commitment of commitment.h with SHA-256 tag blocks, as in
 * binius64/src/slh/commit.rs, for the SLH-DSA blind signature.
 *
 * Each of the three hashes, m_hat = H_msg(msg), y = H_com(r) and
 * d = H_sig(enc(M)), is SHA-256 of a 64-byte tag block followed by its input.
 * A tag block is ASCII padded with 0xFF, which keeps these inputs apart from
 * every other SHA-256 input of the scheme:
 * - SLH-DSA's F, H, T_l and PRF start with PK.seed || 0^48: bytes 16..64 zero;
 * - SLH-DSA's inner H_msg hash, with an empty context, has 0x00 0x00 at bytes
 *   48..50 (R || PK.seed || PK.root || 0x00 || 0x00 || d);
 * - HMAC-SHA-256 in PRF_msg starts with K xor ipad/opad: bytes 16..64 all
 *   0x36 or 0x5c;
 * - Longfellow's Fiat–Shamir transcript (random/transcript.h) feeds SHA-256
 *   a stream that starts with the type byte TAG_BSTR = 0x00, while every tag
 *   starts with 'b'.
 * Two SHA-256 uses are not separated by construction. The MGF1 call of H_msg
 * hashes R || PK.seed || inner || 0^4, 68 bytes whose first 64 are not fixed;
 * it matches a tagged input only if the SHA-256 output inner equals bytes
 * 32..64 of a tag and the tagged input is 68 bytes long, which only m_hat of
 * a 4-byte document is (y and d inputs are 160 and 320 bytes). Longfellow's
 * Merkle nodes hash two digests, 64 bytes, as long as m_hat of an empty
 * document. Both need SHA-256 outputs equal to fixed strings.
 * binius64/src/slh/commit.rs does not list the MGF1 case.
 * Being a constant first block, a tag costs nothing in the circuit, which
 * starts from its constant midstate. The tag helpers are commitment.h's,
 * which the XMSS commitment uses with its own labels. */

#ifndef BLIND_LONGFELLOW_SLH_COMMIT_H_
#define BLIND_LONGFELLOW_SLH_COMMIT_H_

#include <array>
#include <cstdint>
#include <utility>

#include "commitment.h"
#include "field.h"
#include "rng.h"
#include "sha.h"
#include "slh/native.h"

namespace blind_longfellow {
namespace slh {

extern const Tag kTagMessage;  // "blind-slh-dsa/sha256/v1/message-hash"
extern const Tag kTagNonce;    // "blind-slh-dsa/sha256/v1/commitment-y"
extern const Tag kTagDigest;   // "blind-slh-dsa/sha256/v1/commitment-d"

// m_hat = SHA-256(TAG_MESSAGE || msg).
Hash message_hash(const uint8_t* msg, size_t len);
inline Hash message_hash(const Bytes& msg) {
  return message_hash(msg.data(), msg.size());
}
// y = SHA-256(TAG_NONCE || r_0 || ... || r_5).
Hash nonce_hash(const std::array<FeBytes, kNNonce>& r);
// d = SHA-256(TAG_DIGEST || a || b || y), the message SLH-DSA signs.
Hash com_digest(const HmCommitment& com);

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r);
std::pair<HmCommitment, CommitmentOpening> sample_commitment(const Field& F,
                                                             Rng& rng,
                                                             const Bytes& msg);
bool verify_opening(const Field& F, const HmCommitment& com, const Bytes& msg,
                    const std::array<FeBytes, kNNonce>& r);

}  // namespace slh
}  // namespace blind_longfellow

#endif
