/* SLH-DSA parameter sets at security category 1 (n = 16), FIPS 205 Section 11
 * and SP 800-230 ipd Table 1. Derived sizes follow FIPS 205 (5.1), (5.2) and
 * Algorithms 7 and 19. */

#ifndef BLIND_LONGFELLOW_SLH_PARAMS_H_
#define BLIND_LONGFELLOW_SLH_PARAMS_H_

#include <cstddef>

namespace blind_longfellow {
namespace slh {

constexpr size_t kN = 16;

struct SlhParams {
  const char* name;
  size_t h;     // hypertree height
  size_t d;     // hypertree layers
  size_t hp;    // XMSS tree height h' = h / d
  size_t a;     // FORS tree height
  size_t k;     // FORS trees
  size_t lg_w;  // log2 of the Winternitz parameter
  size_t m;     // message-digest bytes

  constexpr size_t w() const { return size_t{1} << lg_w; }
  constexpr size_t len1() const { return (8 * kN + lg_w - 1) / lg_w; }
  constexpr size_t len2() const {
    size_t x = len1() * (w() - 1), floor_log2 = 0;
    while (x >>= 1) ++floor_log2;
    return floor_log2 / lg_w + 1;
  }
  constexpr size_t len() const { return len1() + len2(); }
  constexpr size_t csum_shift() const { return (8 - (len2() * lg_w) % 8) % 8; }
  constexpr size_t csum_bytes() const { return (len2() * lg_w + 7) / 8; }
  constexpr size_t md_bytes() const { return (k * a + 7) / 8; }
  constexpr size_t tree_bits() const { return h - hp; }
  constexpr size_t tree_bytes() const { return (tree_bits() + 7) / 8; }
  constexpr size_t leaf_bytes() const { return (hp + 7) / 8; }
  constexpr size_t sig_bytes() const {
    return kN * (1 + k * (1 + a) + h + d * len());
  }
  constexpr bool consistent() const {
    return md_bytes() + tree_bytes() + leaf_bytes() == m && hp * d == h &&
           tree_bits() <= 64 && hp <= 32 && a <= 31 && lg_w <= 8;
  }
};

// SP 800-230 ipd (April 2026), Table 1: at most 2^24 signatures per key.
constexpr SlhParams kSlhSha2_128_24{"SLH-DSA-SHA2-128-24", 22, 1, 22, 24, 6, 2, 21};

// The toy sets of binius64/tests/slh_dsa.rs: one layer with w = 4 (the shape
// of 128-24), and three layers with w = 16.
constexpr SlhParams kSlhToyW4{"toy-w4-d1", 6, 1, 6, 5, 6, 2, 5};
constexpr SlhParams kSlhToyW16{"toy-w16-d3", 6, 3, 2, 4, 5, 4, 5};

static_assert(kSlhSha2_128_24.len1() == 64 && kSlhSha2_128_24.len2() == 4);
static_assert(kSlhSha2_128_24.sig_bytes() == 3856);
static_assert(kSlhSha2_128_24.consistent() && kSlhToyW4.consistent() &&
              kSlhToyW16.consistent());

}  // namespace slh
}  // namespace blind_longfellow

#endif
