#ifndef BLIND_LONGFELLOW_SHA_WITNESS_ENCODING_H_
#define BLIND_LONGFELLOW_SHA_WITNESS_ENCODING_H_

#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "field.h"

namespace blind_longfellow {

using ShaWordEncoder = proofs::BitPluckerEncoder<Field, kPluckerSize>;

inline void push_bytes(proofs::DenseFiller<Field>& fill, const Field& F,
                       const uint8_t* bytes, size_t n) {
  for (size_t i = 0; i < n; ++i)
    fill.push_back(static_cast<uint64_t>(bytes[i]), 8, F);
}

inline void push_block_witness(proofs::DenseFiller<Field>& fill, ShaWordEncoder& enc,
                               const proofs::FlatSHA256Witness::BlockWitness& bw) {
  for (size_t k = 0; k < 48; ++k) fill.push_back(enc.mkpacked_v32(bw.outw[k]));
  for (size_t k = 0; k < 64; ++k) {
    fill.push_back(enc.mkpacked_v32(bw.oute[k]));
    fill.push_back(enc.mkpacked_v32(bw.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) fill.push_back(enc.mkpacked_v32(bw.h1[k]));
}

}  // namespace blind_longfellow

#endif
