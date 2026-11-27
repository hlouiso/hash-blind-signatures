// Adapted from PoMFRIT, conservative_bs/owf_proof.inc, b984d1f141e3.
// See THIRD_PARTY.md for source revisions, attribution and license notices.
#pragma once
#include "quicksilver.hpp"
#include <cstring>
#include <array>

namespace voleith {
using namespace faest;
inline constexpr size_t VOLEKECCAK_W = 64, VOLEKECCAK_B = 1600;

struct KeccakConstants {
  constexpr static std::size_t ROTATION_OFFSET[25] = {
      0,  36, 3,  41, 18, 1,  44, 10, 45, 2,  62, 6,  43,
      15, 61, 28, 55, 25, 21, 56, 27, 20, 39, 8,  14,
  };
  constexpr static std::size_t ROUND_CONST[24] = {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
      0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
  };
};

template <class QS>
quicksilver_gfsecpar<QS, 0> load_const_1_bit_and_combine(const QS* qs,
                                                         const uint8_t* data,
                                                         size_t bit) {
  return quicksilver_gfsecpar<QS, 0>(poly1::load(*data, bit), qs);
}

template <secpar S, bool flag, size_t max_deg, size_t deg1>
  requires(deg1 <= max_deg)
quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg1>* get_lane(
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg1>* state,
    size_t x, size_t y) {
  return &state[(x * 5 + y) * VOLEKECCAK_W];
}

template <secpar S, bool flag, size_t max_deg, size_t deg1, size_t deg2,
          size_t deg3>
  requires(deg1 <= max_deg && deg2 <= max_deg && deg3 <= max_deg)
void add_lane(
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg1>* lane_out,
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg2>* lane_a,
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg3>* lane_b) {
  for (size_t i = 0; i < VOLEKECCAK_W; i++) {
    lane_out[i] = lane_a[i] + lane_b[i];
  }
}

template <secpar S, bool flag, size_t max_deg, size_t deg1, size_t deg2>
  requires(deg1 <= max_deg && deg2 <= max_deg)
void rot_lane(
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg1>* rot_lane,
    quicksilver_gfsecpar<quicksilver_state<S, flag, max_deg>, deg2>* lane,
    size_t shift) {
  for (size_t i = 0; i < VOLEKECCAK_W; i++) {
    rot_lane[(i + shift) % VOLEKECCAK_W] = lane[i];
  }
}

template <typename QS, size_t deg_in, size_t deg_out>
void keccak_forward(QS* qs_state, size_t round_idx,
                    quicksilver_gfsecpar<QS, deg_in>* state_in,
                    quicksilver_gfsecpar<QS, deg_out>* state_out,
                    size_t output_bits = 1600) {
  using OC = KeccakConstants;

  quicksilver_gfsecpar<QS, deg_in> C[5 * VOLEKECCAK_W];
  for (size_t x = 0; x < 5; x++) {
    add_lane(get_lane(C, 0, x), get_lane(state_in, 0, x),
             get_lane(state_in, 1, x));
    add_lane(get_lane(C, 0, x), get_lane(C, 0, x), get_lane(state_in, 2, x));
    add_lane(get_lane(C, 0, x), get_lane(C, 0, x), get_lane(state_in, 3, x));
    add_lane(get_lane(C, 0, x), get_lane(C, 0, x), get_lane(state_in, 4, x));
  }

  quicksilver_gfsecpar<QS, deg_in> D[5 * VOLEKECCAK_W];
  for (size_t x = 0; x < 5; x++) {
    quicksilver_gfsecpar<QS, deg_in> C_rot[VOLEKECCAK_W];
    rot_lane(C_rot, get_lane(C, 0, (x + 1) % 5), 1);
    add_lane(get_lane(D, 0, x), get_lane(C, 0, (x + 4) % 5), C_rot);
  }

  // Apply theta as each lane is rotated and moved by rho/pi. The state is
  // row-major; ROTATION_OFFSET is indexed by (column, row).
  quicksilver_gfsecpar<QS, deg_in> B_fwd[VOLEKECCAK_B];
  for (size_t row = 0; row < 5; ++row) {
    for (size_t col = 0; col < 5; ++col) {
      const auto* in = get_lane(state_in, row, col);
      const auto* delta = get_lane(D, 0, col);
      auto* out = get_lane(B_fwd, (2 * col + 3 * row) % 5, row);
      const auto rot = OC::ROTATION_OFFSET[5 * col + row];
      for (size_t z = 0; z < 64; ++z) out[(z + rot) % 64] = in[z] + delta[z];
    }
  }

  const uint8_t one_byte = 1;
  const auto one = load_const_1_bit_and_combine(qs_state, &one_byte, 0);
  for (size_t row = 0; row < 5; ++row) {
    for (size_t col = 0; col < 5; ++col) {
      if ((5 * row + col) * 64 >= output_bits) continue;
      const auto* a = get_lane(B_fwd, row, col);
      const auto* b = get_lane(B_fwd, row, (col + 1) % 5);
      const auto* c = get_lane(B_fwd, row, (col + 2) % 5);
      auto* out = get_lane(state_out, row, col);
      for (size_t z = 0; z < 64; ++z) out[z] = (b[z] + one) * c[z] + a[z];
    }
  }

  quicksilver_gfsecpar<QS, 0> round_const[VOLEKECCAK_W];
  uint8_t rc_bytes[8];
  memcpy(rc_bytes, &OC::ROUND_CONST[round_idx], 8);
  for (size_t i = 0; i < VOLEKECCAK_W; i++) {
    round_const[i] =
        load_const_1_bit_and_combine(qs_state, &rc_bytes[i / 8], i % 8);
  }
  add_lane(get_lane(state_out, 0, 0), get_lane(state_out, 0, 0), round_const);
}

// On column parities L = I + P^-1 + R*P, P^5 = R^64 = I and L^192 = I.
// Apply L^-1 = L^191 in seven sparse passes to [row][column][bit] storage.
template <class T, class Add>
void inverse_theta(T* state, Add add) {
  std::array<T, 320> parity, next;
  for (size_t x = 0; x < 5; ++x)
    for (size_t z = 0; z < 64; ++z) {
      auto c = state[x * 64 + z];
      for (size_t y = 1; y < 5; ++y) c = add(c, state[(y * 5 + x) * 64 + z]);
      parity[x * 64 + z] = c;
    }
  for (size_t power : {1ul, 2ul, 4ul, 8ul, 16ul, 32ul, 128ul}) {
    const size_t shift = power % 5, rotation = power % 64;
    for (size_t x = 0; x < 5; ++x)
      for (size_t z = 0; z < 64; ++z)
        next[x * 64 + z] =
            add(add(parity[x * 64 + z], parity[((x + 5 - shift) % 5) * 64 + z]),
                parity[((x + shift) % 5) * 64 + (z + 64 - rotation) % 64]);
    parity = next;
  }
  for (size_t x = 0; x < 5; ++x)
    for (size_t z = 0; z < 64; ++z) {
      const auto d = add(parity[((x + 4) % 5) * 64 + z],
                         parity[((x + 1) % 5) * 64 + (z + 63) % 64]);
      for (size_t y = 0; y < 5; ++y)
        state[(y * 5 + x) * 64 + z] = add(state[(y * 5 + x) * 64 + z], d);
    }
}

template <typename QS, size_t deg_in, size_t deg_out>
void keccak_backward(QS* qs_state, size_t round_idx,
                     quicksilver_gfsecpar<QS, deg_in>* state_in,
                     quicksilver_gfsecpar<QS, deg_out>* state_out) {
  using OC = KeccakConstants;

  quicksilver_gfsecpar<QS, 0> round_const[VOLEKECCAK_W];
  uint8_t rc_bytes[8];
  memcpy(rc_bytes, &OC::ROUND_CONST[round_idx], 8);
  for (size_t i = 0; i < VOLEKECCAK_W; i++) {
    round_const[i] =
        load_const_1_bit_and_combine(qs_state, &rc_bytes[i / 8], i % 8);
  }
  add_lane(get_lane(state_in, 0, 0), get_lane(state_in, 0, 0), round_const);

  // Inverse chi on a five-lane row, factored over characteristic two:
  // a_i = b_i + (1 + b_{i+1}) (b_{i+2} + (1 + b_{i+3}) b_{i+4}).
  const uint8_t one_byte = 1;
  const auto one = load_const_1_bit_and_combine(qs_state, &one_byte, 0);
  for (size_t row = 0; row < 5; ++row) {
    for (size_t x = 0; x < 5; ++x) {
      const auto* b0 = get_lane(state_in, row, x);
      const auto* b1 = get_lane(state_in, row, (x + 1) % 5);
      const auto* b2 = get_lane(state_in, row, (x + 2) % 5);
      const auto* b3 = get_lane(state_in, row, (x + 3) % 5);
      const auto* b4 = get_lane(state_in, row, (x + 4) % 5);
      // Undo pi and rho while writing inverse chi, before inverse theta.
      const size_t src_row = x, src_col = (3 * row + x) % 5;
      const size_t rot = OC::ROTATION_OFFSET[5 * src_col + src_row];
      auto* out = get_lane(state_out, src_row, src_col);
      for (size_t z = 0; z < 64; ++z) {
        const auto inner = (b3[z] + one) * b4[z] + b2[z];
        out[(z + 64 - rot) % 64] = inner * (b1[z] + one) + b0[z];
      }
    }
  }

  inverse_theta(state_out, [](const auto& a, const auto& b) { return a + b; });
}

}
