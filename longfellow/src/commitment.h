/* Halevi–Micali commitment over GF(2^128), (n,s,k) = (128,2,6), encoded as
 * a || b || y with little-endian polynomial-basis field elements. */

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

HmCommitment hm_commit(const Field& F, const Bytes& msg,
                       const std::array<std::array<FeBytes, kNNonce>, kNLines>& a,
                       const std::array<FeBytes, kNNonce>& r);

std::pair<HmCommitment, CommitmentOpening> sample_commitment(const Field& F,
                                                             Rng& rng,
                                                             const Bytes& msg);

bool verify_hm_opening(const Field& F, const HmCommitment& com,
                       const Bytes& msg,
                       const std::array<FeBytes, kNNonce>& r);

Bytes hm_com_digest_preimage(const HmCommitment& com);
Hash hm_com_digest(const HmCommitment& com);

}

#endif
