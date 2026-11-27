/* Halevi–Micali commitment over GF(2^128), (n,s,k) = (128,2,6), encoded as
 * a || b || y with little-endian polynomial-basis field elements.
 *
 * Each of the three hashes, m_hat = H_msg(msg), y = H_com(r) and
 * d = H_sig(enc(M)), is SHA-256 of a 64-byte tag block followed by its input,
 * as in binius64/src/commitment.rs (XMSS_TAGS), whose vectors
 * ../test-vectors/xmss checks. A tag block is ASCII padded with 0xFF, which
 * keeps these inputs apart from every other SHA-256 input of the scheme:
 * - the XMSS hashes of sha.h start with pk_seed || tweak, a tweak in 0..3 at
 *   byte 16, where every tag has an ASCII character;
 * - HMAC-SHA-256 in the key derivation and the nonce search starts with
 *   K xor ipad/opad: bytes 16..64 all 0x36 or 0x5c, where a tag has 0xFF at
 *   bytes 48..64;
 * - Longfellow's Fiat–Shamir transcript feeds SHA-256 a stream that starts
 *   with the type byte TAG_BSTR = 0x00, while every tag starts with 'b'.
 * Longfellow's Merkle nodes hash two digests, 64 bytes, as long as m_hat of
 * an empty document, so they match it only if two SHA-256 outputs equal the
 * halves of the message tag. The SLH-DSA variant (slh/commit.h) uses its own
 * labels. Being a constant first block, a tag costs nothing in the circuit,
 * which starts from its constant midstate. */

#ifndef BLIND_LONGFELLOW_COMMITMENT_H_
#define BLIND_LONGFELLOW_COMMITMENT_H_

#include <array>
#include <cstdint>
#include <utility>

#include "field.h"
#include "rng.h"
#include "sha.h"

namespace blind_longfellow {

constexpr size_t kNNonce = 6;
constexpr size_t kNLines = 2;
constexpr size_t kFeBytes = 16;

using FeBytes = std::array<uint8_t, kFeBytes>;

struct HmCommitment {
  std::array<std::array<FeBytes, kNNonce>, kNLines> a;
  std::array<FeBytes, kNLines> b;
  Hash y;
};

constexpr size_t kComBytes =
    kNLines * kNNonce * kFeBytes + kNLines * kFeBytes + kHashBytes;

struct CommitmentOpening {
  Bytes msg;
  std::array<FeBytes, kNNonce> r;
};

constexpr size_t kTagBytes = 64;
using Tag = std::array<uint8_t, kTagBytes>;

// An ASCII label of at most 48 bytes, padded with 0xFF to one SHA-256 block.
Tag tag_block(const char* label);
// SHA-256(tag || data).
Hash tagged(const Tag& tag, const uint8_t* data, size_t len);
// The SHA-256 state after the tag block.
Midstate tag_midstate(const Tag& tag);

extern const Tag kXmssTagMessage;  // "blind-xmss/sha256/v1/message-hash"
extern const Tag kXmssTagNonce;    // "blind-xmss/sha256/v1/commitment-y"
extern const Tag kXmssTagDigest;   // "blind-xmss/sha256/v1/commitment-d"

// m_hat = SHA-256(TAG_MESSAGE || msg), the public input.
Hash hm_message_hash(const Bytes& msg);
// y = SHA-256(TAG_NONCE || r_0 || ... || r_5).
Hash hm_nonce_hash(const std::array<FeBytes, kNNonce>& r);

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r);

std::pair<HmCommitment, CommitmentOpening> sample_commitment(const Field& F,
                                                             Rng& rng,
                                                             const Bytes& msg);

bool verify_hm_opening(const Field& F, const HmCommitment& com,
                       const Bytes& msg,
                       const std::array<FeBytes, kNNonce>& r);

// a || b || y, the input of H_sig after its tag.
Bytes hm_com_digest_preimage(const HmCommitment& com);
// d = SHA-256(TAG_DIGEST || a || b || y), the message XMSS signs.
Hash hm_com_digest(const HmCommitment& com);

}

#endif
