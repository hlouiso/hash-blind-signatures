#ifndef BLIND_LONGFELLOW_CIRCUIT_SHA_WORD_PLUCKER_H_
#define BLIND_LONGFELLOW_CIRCUIT_SHA_WORD_PLUCKER_H_

#include <array>

#include "circuits/logic/bit_plucker.h"
#include "field.h"
#include "util/panic.h"

namespace blind_longfellow {

// Longfellow's encoder maps four bits onto an affine binary subspace of
// GF(2^128). Each interpolated coordinate is an affine linearized polynomial
// c0 + c1*x + c2*x^2 + c4*x^4 + c8*x^8. Share those powers across the bits.
template <class LC>
class ShaWordPlucker : public proofs::BitPlucker<LC, kPluckerSize> {
  using Base = proofs::BitPlucker<LC, kPluckerSize>;
  using EltW = typename LC::EltW;

 public:
  explicit ShaWordPlucker(const LC& L) : Base(L) {
    static_assert(kPluckerSize == 4);
    for (const auto& p : this->plucker_)
      for (size_t i = 1; i < Base::kN; ++i)
        if ((i & (i - 1)) != 0)
          proofs::check(p[i] == L.f_.zero(), "unexpected SHA word encoding polynomial");
  }

  typename LC::v32 unpack_v32(const typename Base::packed_v32& packed) const {
    const LC& L = this->l_;
    typename LC::v32 out;
    for (size_t j = 0; j < packed.size(); ++j) {
      std::array<EltW, kPluckerSize> powers;
      powers[0] = packed[j];
      for (size_t i = 1; i < powers.size(); ++i)
        powers[i] = L.mul(powers[i - 1], powers[i - 1]);
      for (size_t bit = 0; bit < powers.size(); ++bit) {
        const auto& p = this->plucker_[bit];
        EltW v = L.konst(p[0]);
        for (size_t i = 0; i < powers.size(); ++i)
          v = L.add(v, L.mul(p[1u << i], powers[i]));
        // p0(x)*(p0(x)+1) is nonzero (coordinate 0 is nonconstant),
        // has degree at most 16, and vanishes at all 16 encoder points.
        // These are all its roots, so checking one bit proves membership.
        if (bit == 0) L.assert_is_bit(v);
        out[j * powers.size() + bit] = typename LC::BitW(v, L.f_);
      }
    }
    return out;
  }
};
}  // namespace blind_longfellow

#endif
