#pragma once
#include "keccak_constraints.hpp"
#include <array>
#include <span>
#include <stdexcept>
#include <vector>
extern "C" {
#include "native/xmss.h"
#include "native/commitment.h"
#include "native/hash.h"
void pomfrit_permute_trace(uint64_t state[25], uint64_t trace[100]);
}

namespace voleith {
inline constexpr size_t kProofDegree = VOLEITH_DEGREE;
inline constexpr size_t kVoleTrees = VOLEITH_TAU;
inline constexpr size_t kGrindingBits = VOLEITH_GRIND;
inline constexpr size_t kKeccakStride =
    kProofDegree == 16 ? 6 : (kProofDegree == 32 ? 8 : 9);
inline constexpr size_t kKeccakSnapshots = 24 / kKeccakStride;
using Bytes = std::vector<uint8_t>;
inline constexpr size_t kPrimaryBytes =
    HM_R_BYTES + HM_A_BYTES + XMSS_SIG_BYTES + 99 + 42 * 16;
inline constexpr size_t kSigOffset = HM_R_BYTES + HM_A_BYTES;
inline constexpr size_t kScheduleOffset = kSigOffset + XMSS_SIG_BYTES;
inline constexpr size_t kEndpointsOffset = kScheduleOffset + 99;

struct Statement {
  std::array<uint8_t, 32> message;
  std::array<uint8_t, 16> pk_seed;
  std::array<uint8_t, 16> root;
};

// Native and authenticated evaluation must share witness and constraint order.
struct NativeContext {
  static constexpr bool native = true;
  using Bit = uint8_t;
  Bytes witness;
  size_t cursor = kPrimaryBytes * 8, constraints = 0, permutations = 0;
  bool check = true;

  explicit NativeContext(Bytes primary, bool validate = true)
      : witness(std::move(primary)), check(validate) {
    witness.resize(kPrimaryBytes);
  }

  Bit constant(unsigned b) const { return b & 1; }

  Bit bit(size_t i) const { return (witness.at(i / 8) >> (i % 8)) & 1; }

  Bit allocate(unsigned value = 0) {
    if (cursor / 8 >= witness.size()) witness.push_back(0);
    witness[cursor / 8] |= (value & 1) << (cursor % 8);
    ++cursor;
    return value & 1;
  }

  Bit add(Bit a, Bit b) const { return a ^ b; }

  Bit mul(Bit a, Bit b) {
    ++constraints;
    return allocate(a & b);
  }

  void zero(Bit a) {
    ++constraints;
    if (check && a)
      throw std::invalid_argument("unsatisfied Boolean constraint");
  }

  void zero(poly128 a) {
    ++constraints;
    if (check && !(a == poly128::set_zero()))
      throw std::invalid_argument("unsatisfied field constraint");
  }

  poly128 pack(std::span<const Bit> bits) const {
    std::array<uint8_t, 16> b{};
    if (bits.size() > 128) throw std::logic_error("field packing overflow");
    for (size_t i = 0; i < bits.size(); ++i) b[i / 8] |= bits[i] << (i % 8);
    return poly128::load_dup(b.data());
  }

  poly128 product(poly128 a, poly128 b) const {
    return (a * b).reduce_to<128>();
  }

  std::vector<Bit> field_witness(poly128 a, size_t bits = 128) {
    std::array<uint8_t, 16> b{};
    a.store(b.data());
    std::vector<Bit> out(bits);
    for (size_t i = 0; i < bits; ++i)
      out[i] = allocate((b[i / 8] >> (i % 8)) & 1);
    zero(a + pack(out));
    return out;
  }

  std::vector<Bit> permute(std::vector<Bit> state, size_t keep = 1600) {
    alignas(8) uint64_t words[25]{}, trace[100]{};
    for (size_t i = 0; i < 1600; ++i)
      words[i / 64] |= uint64_t(state[i]) << (i % 64);
    pomfrit_permute_trace(words, trace);
    for (size_t j = 0; j < kKeccakSnapshots; ++j)
      for (size_t i = 0; i < 1600; ++i) {
        auto b = allocate((trace[j * 25 + i / 64] >> (i % 64)) & 1);
        if (j + 1 == kKeccakSnapshots) state[i] = b;
      }
    constraints += 1600 * kKeccakSnapshots;
    if constexpr (kProofDegree == 64) {
      state.resize(keep);
      for (size_t i = 0; i < keep; ++i)
        state[i] = allocate((words[i / 64] >> (i % 64)) & 1);
      constraints += keep;
    }
    ++permutations;
    return state;
  }
};

template <bool Verify>
struct AuthContext {
  static constexpr bool native = false;
  using QS = quicksilver_state<secpar::s128, Verify, kProofDegree>;
  using Bit = quicksilver_gfsecpar<QS, 1>;
  QS& qs;
  size_t cursor = kPrimaryBytes * 8, constraints = 0, permutations = 0;

  explicit AuthContext(QS& q) : qs(q) {}

  Bit constant(unsigned b) const { return Bit(poly1::load(b, 0), &qs); }

  Bit bit(size_t i) const { return Bit(qs.get_witness_bit(i)); }

  Bit allocate(unsigned = 0) { return bit(cursor++); }

  Bit add(const Bit& a, const Bit& b) const { return a + b; }

  Bit mul(const Bit& a, const Bit& b) {
    auto c = allocate();
    zero(a * b + c);
    return c;
  }

  template <size_t D>
  void zero(quicksilver_gfsecpar<QS, D> a) {
    ++constraints;
    qs.add_constraint(a);
  }

  Bit pack(std::span<const Bit> bits) const {
    Bit result = constant(0);
    for (size_t i = 0; i < bits.size(); ++i) {
      std::array<uint8_t, 16> coefficient{};
      coefficient[i / 8] = uint8_t(1u << (i % 8));
      result += bits[i] * poly128::load_dup(coefficient.data());
    }
    return result;
  }

  template <class A, class B>
  auto product(const A& a, const B& b) const {
    return a * b;
  }

  template <class A>
  std::vector<Bit> field_witness(const A& a, size_t bits = 128) {
    std::vector<Bit> out(bits);
    for (auto& b : out) b = allocate();
    zero(a + pack(out));
    return out;
  }

  template <size_t D>
  std::vector<Bit> meet(const std::vector<quicksilver_gfsecpar<QS, D>>& forward,
                        size_t last) {
    std::vector<Bit> state(1600);
    for (auto& b : state) b = allocate();
    auto backwards = state;  // inverse iota mutates its input
    std::vector<quicksilver_gfsecpar<QS, 3>> b3(1600);
    std::vector<quicksilver_gfsecpar<QS, 9>> b9(1600);
    keccak_backward<QS, 1, 3>(&qs, last, backwards.data(), b3.data());
    keccak_backward<QS, 3, 9>(&qs, last - 1, b3.data(), b9.data());
    if constexpr (D == 16) {
      for (size_t i = 0; i < 1600; ++i) zero(forward[i] + b9[i]);
    } else {
      std::vector<quicksilver_gfsecpar<QS, 27>> b27(1600);
      keccak_backward<QS, 9, 27>(&qs, last - 2, b9.data(), b27.data());
      for (size_t i = 0; i < 1600; ++i) zero(forward[i] + b27[i]);
    }
    return state;
  }

  std::vector<Bit> permute(std::vector<Bit> state, size_t keep = 1600) {
    for (size_t round = 0; round < 24; round += kKeccakStride) {
      std::vector<quicksilver_gfsecpar<QS, 2>> f2(1600);
      std::vector<quicksilver_gfsecpar<QS, 4>> f4(1600);
      std::vector<quicksilver_gfsecpar<QS, 8>> f8(1600);
      std::vector<quicksilver_gfsecpar<QS, 16>> f16(1600);
      keccak_forward<QS, 1, 2>(&qs, round, state.data(), f2.data());
      keccak_forward<QS, 2, 4>(&qs, round + 1, f2.data(), f4.data());
      keccak_forward<QS, 4, 8>(&qs, round + 2, f4.data(), f8.data());
      keccak_forward<QS, 8, 16>(&qs, round + 3, f8.data(), f16.data());
      if constexpr (kProofDegree == 16) {
        state = meet(f16, round + 5);
      } else {
        std::vector<quicksilver_gfsecpar<QS, 32>> f32(1600);
        keccak_forward<QS, 16, 32>(&qs, round + 4, f16.data(), f32.data());
        if constexpr (kProofDegree == 32) {
          state = meet(f32, round + 7);
        } else {
          std::vector<quicksilver_gfsecpar<QS, 64>> f64(1600);
          keccak_forward<QS, 32, 64>(&qs, round + 5, f32.data(), f64.data(),
                                     round == 18 ? keep : 1600);
          if (round == 18) {
            // Commit only the digest bits, or the state for another absorption.
            state.resize(keep);
            for (size_t i = 0; i < keep; ++i) {
              state[i] = allocate();
              zero(f64[i] + state[i]);
            }
          } else
            state = meet(f64, round + 8);
        }
      }
    }
    ++permutations;
    return state;
  }
};

template <class E>
class Circuit {
 public:
  using Bit = typename E::Bit;
  using Bits = std::vector<Bit>;
  E& e;

  explicit Circuit(E& engine) : e(engine) {}

  Bits constant(std::span<const uint8_t> b) {
    Bits out;
    out.reserve(b.size() * 8);
    for (auto v : b)
      for (size_t i = 0; i < 8; ++i) out.push_back(e.constant(v >> i));
    return out;
  }

  Bits number(uint64_t v, size_t bits) {
    Bits out(bits);
    for (size_t i = 0; i < bits; ++i) out[i] = e.constant(i < 64 ? v >> i : 0);
    return out;
  }

  Bits input(size_t byte_offset, size_t bytes) {
    Bits out(bytes * 8);
    for (size_t i = 0; i < out.size(); ++i) out[i] = e.bit(byte_offset * 8 + i);
    return out;
  }

  static Bits slice(const Bits& x, size_t off, size_t n) {
    return Bits(x.begin() + off, x.begin() + off + n);
  }

  static void append(Bits& a, const Bits& b) {
    a.insert(a.end(), b.begin(), b.end());
  }

  Bit invert(const Bit& b) { return e.add(b, e.constant(1)); }

  Bit equal(const Bits& a, const Bits& b) {
    if (a.empty()) return e.constant(1);
    auto result = invert(e.add(a[0], b[0]));
    for (size_t i = 1; i < a.size(); ++i)
      result = e.mul(result, invert(e.add(a[i], b[i])));
    return result;
  }

  Bits chain_flags(const Bits& index) {
    e.zero(index[6]);
    e.zero(index[7]);
    Bits flags{invert(index[5]), index[5]};
    // Share p*x between both children; discard prefixes >=42.
    for (int bit = 4; bit >= 0; --bit) {
      const size_t count = (42 + (size_t(1) << bit) - 1) >> bit;
      Bits next;
      next.reserve(count);
      for (size_t i = 0; i < flags.size(); ++i) {
        auto one = e.mul(flags[i], index[bit]);
        next.push_back(e.add(flags[i], one));
        if (2 * i + 1 < count) next.push_back(one);
      }
      flags = std::move(next);
    }
    return flags;
  }

  Bit less(const Bits& a, const Bits& b) {
    auto result = e.constant(0);
    for (size_t i = 0; i < a.size(); ++i) {
      auto same = invert(e.add(a[i], b[i]));
      result = e.add(e.mul(same, result), e.mul(invert(a[i]), b[i]));
    }
    return result;
  }

  Bits add(const Bits& a, const Bits& b, bool no_overflow = false) {
    Bits out(a.size());
    auto carry = e.constant(0);
    for (size_t i = 0; i < a.size(); ++i) {
      out[i] = e.add(e.add(a[i], b[i]), carry);
      carry = e.add(e.mul(e.add(a[i], carry), e.add(b[i], carry)), carry);
    }
    if (no_overflow) e.zero(carry);
    return out;
  }

  Bits select(const Bit& flag, const Bits& yes, const Bits& no) {
    Bits out(yes.size());
    for (size_t i = 0; i < out.size(); ++i)
      out[i] = e.add(no[i], e.mul(flag, e.add(yes[i], no[i])));
    return out;
  }

  Bits shake(const Bits& input_bits, size_t output_bytes) {
    if (input_bits.size() % 8 || output_bytes > 136)
      throw std::logic_error("SHAKE circuit size");
    Bits padded = input_bits;
    append(padded, number(0x1f, 8));
    while (padded.size() % 1088) padded.push_back(e.constant(0));
    padded.back() = e.add(padded.back(), e.constant(1));
    auto state = number(0, 1600);
    for (size_t off = 0; off < padded.size(); off += 1088) {
      for (size_t i = 0; i < 1088; ++i)
        state[i] = e.add(state[i], padded[off + i]);
      state = e.permute(std::move(state),
                        off + 1088 == padded.size() ? output_bytes * 8 : 1600);
    }
    state.resize(output_bytes * 8);
    return state;
  }

  Bits hash(const Bits& domain, const Bits& data, size_t out = 32) {
    auto prefix =
        constant(std::span(reinterpret_cast<const uint8_t*>(SHAKE_APP_PREFIX),
                           SHAKE_APP_PREFIX_BYTES));
    append(prefix, number(domain.size() / 8, 8));
    append(prefix, domain);
    append(prefix, data);
    return shake(prefix, out);
  }

  Bits hash(const char* domain, const Bits& data, size_t out = 32) {
    return hash(constant(std::span(reinterpret_cast<const uint8_t*>(domain),
                                   std::strlen(domain))),
                data, out);
  }

  void equal_field(const Bits& a, const Bits& b) {
    e.zero(e.pack(a) + e.pack(b));
  }

  void statement(const Statement& pub) {
    auto r = input(0, 96), a = input(96, 192);
    auto m = constant(pub.message), seed = constant(pub.pk_seed);
    Bits b;
    for (size_t line = 0; line < 2; ++line) {
      auto sum = e.product(e.pack(slice(a, line * 768, 128)),
                           e.pack(slice(r, 0, 128)));
      for (size_t i = 1; i < 6; ++i)
        sum = sum + e.product(e.pack(slice(a, line * 768 + i * 128, 128)),
                              e.pack(slice(r, i * 128, 128)));
      append(b, e.field_witness(sum + e.pack(slice(m, line * 128, 128))));
    }
    auto y = hash("HMy", r);
    Bits com = a;
    append(com, b);
    append(com, y);
    auto d = hash("HMd", com);
    auto epoch = input(kSigOffset, 4), nonce = input(kSigOffset + 4, 24);
    Bits epoch_be;
    for (size_t i = 0; i < 4; ++i)
      append(epoch_be, slice(epoch, (3 - i) * 8, 8));
    Bits msg_dom = seed;
    append(msg_dom, number(XMSS_TWEAK_MESSAGE, 8));
    append(msg_dom, epoch_be);
    Bits msg = nonce;
    append(msg, d);
    auto digest = hash(msg_dom, msg);
    e.zero(digest[63]);
    e.zero(digest[127]);
    std::array<Bits, 42> coords, tips, ends;
    auto total = number(0, 9);
    for (size_t i = 0; i < 42; ++i) {
      coords[i] = slice(digest, xmss_coord_bit_pos(i), 3);
      auto term = coords[i];
      term.resize(9, e.constant(0));
      total = add(total, term);
      tips[i] = input(kSigOffset + 28 + 16 * i, 16);
      ends[i] = input(kEndpointsOffset + 16 * i, 16);
      auto complete = equal(coords[i], number(7, 3));
      e.zero(e.product(e.pack(std::span(&complete, 1)),
                       e.pack(tips[i]) + e.pack(ends[i])));
    }
    equal_field(total, number(195, 9));
    auto previous_index = number(0, 8), previous_pos = number(0, 3),
         previous_out = number(0, 128);
    for (size_t step = 0; step < 99; ++step) {
      auto index = input(kScheduleOffset + step, 1);
      auto flags = chain_flags(index);
      auto flag_sum = e.constant(0);
      for (const auto& flag : flags) flag_sum = e.add(flag_sum, flag);
      e.zero(invert(flag_sum));
      auto same = step ? equal(index, previous_index) : e.constant(0);
      if (step) {
        e.zero(less(index, previous_index));
        e.zero(e.product(e.pack(std::span(&same, 1)) + e.pack(number(1, 1)),
                         e.pack(previous_pos) + e.pack(number(7, 3))));
      }
      auto selected_tip =
          e.product(e.pack(std::span(&flags[0], 1)), e.pack(tips[0]));
      auto selected_end =
          e.product(e.pack(std::span(&flags[0], 1)), e.pack(ends[0]));
      auto selected_coord =
          e.product(e.pack(std::span(&flags[0], 1)), e.pack(coords[0]));
      for (size_t i = 1; i < 42; ++i) {
        auto flag = e.pack(std::span(&flags[i], 1));
        selected_tip = selected_tip + e.product(flag, e.pack(tips[i]));
        selected_end = selected_end + e.product(flag, e.pack(ends[i]));
        selected_coord = selected_coord + e.product(flag, e.pack(coords[i]));
      }
      auto coordinate = e.field_witness(selected_coord, 3);
      auto position =
          add(select(same, previous_pos, coordinate), number(1, 3), true);
      auto sf = e.pack(std::span(&same, 1));
      auto in_node = e.field_witness(
          e.product(sf, selected_tip + e.pack(previous_out)) + selected_tip);
      auto chain_dom = in_node;
      append(chain_dom, number(XMSS_TWEAK_CHAIN, 8));
      auto chain_data = seed;
      append(chain_data, epoch_be);
      append(chain_data, index);
      auto position_byte = position;
      position_byte.resize(8, e.constant(0));
      append(chain_data, position_byte);
      auto out_node = hash(chain_dom, chain_data, 16);
      auto last = equal(position, number(7, 3));
      e.zero(e.product(e.pack(std::span(&last, 1)),
                       selected_end + e.pack(out_node)));
      previous_index = index;
      previous_pos = position;
      previous_out = out_node;
    }
    equal_field(previous_pos, number(7, 3));
    Bits endpoints;
    for (const auto& end : ends) append(endpoints, end);
    auto leaf_dom = seed;
    append(leaf_dom, number(XMSS_TWEAK_LEAF, 8));
    append(leaf_dom, epoch_be);
    auto node = hash(leaf_dom, endpoints, 16);
    auto idx = epoch;
    for (size_t level = 0; level < 32; ++level) {
      auto sibling = input(kSigOffset + 28 + 42 * 16 + level * 16, 16);
      auto left = select(idx[0], sibling, node);
      Bits right(128);
      for (size_t i = 0; i < 128; ++i)
        right[i] = e.add(e.add(left[i], node[i]), sibling[i]);
      idx.erase(idx.begin());
      idx.push_back(e.constant(0));
      auto tree_dom = seed;
      append(tree_dom, number(XMSS_TWEAK_TREE, 8));
      append(tree_dom, number(level, 8));
      append(tree_dom, idx);
      append(left, right);
      node = hash(tree_dom, left, 16);
    }
    equal_field(node, constant(pub.root));
    // The VOLE API consumes whole bytes. Bind the final padding bits too.
    while (e.cursor % 8) e.zero(e.allocate(0));
  }
};
}
