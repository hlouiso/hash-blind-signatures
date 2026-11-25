#pragma once
// The SLH-DSA-SHAKE blind-signature statement: a Halevi–Micali opening of the
// public m_hat with the tagged SHAKE256 hashes of native/slh_commit.h, and a
// pure SLH-DSA-SHAKE signature (empty context) on
// d = SHAKE256(TAG_DIGEST || a || b || y) under the public key
// (PK.seed, PK.root). A port of binius64/src/slh/gadget.rs.
//
// The primary witness is r || a || SIG, with SIG the FIPS 205 encoding
// R || SIG_FORS || SIG_HT; everything else (b, Keccak snapshots, selected
// chain values, adder carries) is allocated while the circuit runs, in the
// same order for the native and the authenticated engine. The digest,
// indices, addresses and chain digits are computed from the witness and stay
// secret. Every witness value is one bit, so no carry or high-half garbage
// can reach an address byte: the ADRS fields are rewired digest bits.
//
// The WOTS+ chains take all w - 1 steps at hash addresses s = 0 .. w - 2,
// keeping step s exactly when the digit is at most s. The select
// x <- keep ? F(x) : x costs 128 witness bits per step: folding it into the
// next permutation's input would make that input degree 2, and degree-2
// inputs need 5 + 3, 6 + 3 and 6 rounds between the snapshots at degree 64,
// 23 rounds in all, one short of 24 (see the report).
#include "circuit.hpp"
#include <optional>
extern "C" {
#include "native/slh.h"
#include "native/slh_commit.h"
}

namespace voleith {

inline constexpr size_t kSlhROffset = 0;
inline constexpr size_t kSlhAOffset = HM_R_BYTES;
inline constexpr size_t kSlhSigOffset = HM_R_BYTES + HM_A_BYTES;

// constexpr copies of native/slh.c's parameter sets, for templates.
inline constexpr slh_params kSlhShake128_24{"SLH-DSA-SHAKE-128-24", 22, 1, 22, 24, 6, 2, 21};
inline constexpr slh_params kSlhToyW4{"toy-w4-d1", 6, 1, 6, 5, 6, 2, 5};
inline constexpr slh_params kSlhToyW16{"toy-w16-d3", 6, 3, 2, 4, 5, 4, 5};

struct SlhStatement {
  std::array<uint8_t, 32> message;  // m_hat
  std::array<uint8_t, 16> pk_seed, pk_root;
};

// ---------------------------------------------------- dimensions, constexpr

struct SlhDims {
  size_t primary_bytes, witness_bits, constraints, permutations;
};

namespace slh_detail {
constexpr size_t w(const slh_params& p) { return size_t{1} << p.lg_w; }
constexpr size_t len1(const slh_params& p) { return (8 * SLH_N + p.lg_w - 1) / p.lg_w; }
constexpr size_t len2(const slh_params& p) {
  size_t x = len1(p) * (w(p) - 1), lg = 0;
  while (x >>= 1) ++lg;
  return lg / p.lg_w + 1;
}
constexpr size_t len(const slh_params& p) { return len1(p) + len2(p); }
constexpr size_t sig_bytes(const slh_params& p) {
  return SLH_N * (1 + p.k * (1 + p.a) + p.h + p.d * len(p));
}

// Multiplications of SlhCircuit::less_const(x, c) for an n-bit x.
constexpr size_t less_const_muls(size_t n, uint64_t c) {
  int state = 0;  // 0: constant 0, 1: constant 1, 2: a wire
  size_t muls = 0;
  for (size_t i = 0; i < n; ++i) {
    const bool one = (c >> i) & 1;
    if (state == 2) {
      ++muls;
    } else if (one) {
      state = state == 0 ? 2 : 1;  // !x OR 0 = !x; !x OR 1 = 1
    } else {
      state = state == 0 ? 0 : 2;  // !x AND 0 = 0; !x AND 1 = !x
    }
  }
  return muls;
}

// Multiplications of SlhCircuit::sum_tree over `count` numbers of `bits`.
constexpr size_t sum_tree_muls(size_t count, size_t bits) {
  size_t muls = 0;
  while (count > 1) {
    muls += (count / 2) * bits;
    count = count / 2 + count % 2;
    ++bits;
  }
  return muls;
}
}  // namespace slh_detail

constexpr SlhDims slh_dims(const slh_params& p) {
  using namespace slh_detail;
  const size_t snap = 1600 * kKeccakSnapshots;
  const bool deg64 = kProofDegree == 64;
  size_t bits = 0, cons = 0, perms = 0;
  auto perm = [&](size_t keep) {
    bits += snap + (deg64 ? keep : 0);
    cons += snap + (deg64 ? keep : 0);
    ++perms;
  };
  auto shake = [&](size_t in_bytes, size_t out_bytes) {
    const size_t blocks = (in_bytes + 1 + 135) / 136;
    for (size_t b = 1; b < blocks; ++b) perm(1600);
    perm(8 * out_bytes);
  };
  auto muls = [&](size_t n) {
    bits += n;
    cons += n;
  };
  const size_t primary = HM_R_BYTES + HM_A_BYTES + sig_bytes(p);
  bits += 8 * primary;
  bits += 256;  // b, two field witnesses
  cons += 2;
  shake(HM_R_BYTES, 32);                     // y, after the tag block
  shake(HM_A_BYTES + HM_B_BYTES + 32, 32);   // d, after the tag block
  shake(3 * SLH_N + 2 + 32, p.m);            // H_msg
  const size_t th = SLH_N + 32;              // PK.seed || ADRS
  for (size_t i = 0; i < p.k; ++i) {
    shake(th + SLH_N, SLH_N);
    for (size_t j = 0; j < p.a; ++j) {
      muls(8 * SLH_N);
      shake(th + 2 * SLH_N, SLH_N);
    }
  }
  shake(th + p.k * SLH_N, SLH_N);  // T_k
  for (size_t layer = 0; layer < p.d; ++layer) {
    muls(sum_tree_muls(len1(p), p.lg_w));
    for (size_t i = 0; i < len(p); ++i)
      for (size_t s = 0; s + 1 < w(p); ++s) {
        shake(th + SLH_N, SLH_N);
        muls(less_const_muls(p.lg_w, s + 1));
        muls(8 * SLH_N);
      }
    shake(th + len(p) * SLH_N, SLH_N);  // T_len
    for (size_t k = 0; k < p.hp; ++k) {
      muls(8 * SLH_N);
      shake(th + 2 * SLH_N, SLH_N);
    }
  }
  cons += 1;  // the root
  const size_t pad = (8 - bits % 8) % 8;
  bits += pad;
  cons += pad;
  return {primary, bits, cons, perms};
}

// ------------------------------------------------------------------ circuit

template <class E>
class SlhCircuit {
 public:
  using Bit = typename E::Bit;
  using Bits = std::vector<Bit>;
  E& e;
  Circuit<E> c;
  const slh_params& p;

  SlhCircuit(E& engine, const slh_params& params) : e(engine), c(engine), p(params) {}

  // SHAKE256 of `input`, absorbed after a full block whose state is `init`
  // (nullptr: the zero state), truncated to out_bytes.
  Bits shake_from(const uint64_t* init, const Bits& input, size_t out_bytes) {
    Bits padded = input;
    Circuit<E>::append(padded, c.number(0x1f, 8));
    while (padded.size() % 1088) padded.push_back(e.constant(0));
    padded.back() = e.add(padded.back(), e.constant(1));
    Bits state(1600);
    for (size_t i = 0; i < 1600; ++i)
      state[i] = e.constant(init ? (init[i / 64] >> (i % 64)) & 1 : 0);
    for (size_t off = 0; off < padded.size(); off += 1088) {
      for (size_t i = 0; i < 1088; ++i) state[i] = e.add(state[i], padded[off + i]);
      state = e.permute(std::move(state),
                        off + 1088 == padded.size() ? out_bytes * 8 : 1600);
    }
    state.resize(out_bytes * 8);
    return state;
  }

  // Bit t of a byte string read as a big-endian bit stream.
  static const Bit& stream_bit(const Bits& x, size_t t) {
    return x[8 * (t / 8) + 7 - t % 8];
  }

  // Bits [start, start + n) of the stream as an integer, LSB first (Alg. 4).
  static Bits stream_int(const Bits& x, size_t start, size_t n) {
    Bits out;
    for (size_t j = 0; j < n; ++j) out.push_back(stream_bit(x, start + n - 1 - j));
    return out;
  }

  // The low `bits` bits of the big-endian integer x[off, off + nbytes).
  Bits be_int(const Bits& x, size_t off, size_t nbytes, size_t bits) {
    Bits out;
    for (size_t j = 0; j < bits; ++j) out.push_back(x[8 * (off + nbytes - 1 - j / 8) + j % 8]);
    return out;
  }

  // The integer v (LSB first) as nbytes big-endian bytes.
  void append_be(Bits& out, const Bits& v, size_t nbytes) {
    for (size_t j = 0; j < nbytes; ++j)
      for (size_t k = 0; k < 8; ++k) {
        const size_t bit = 8 * (nbytes - 1 - j) + k;
        out.push_back(bit < v.size() ? v[bit] : e.constant(0));
      }
  }

  Bits shr(const Bits& v, size_t s) {
    Bits out(v.size(), e.constant(0));
    for (size_t i = s; i < v.size(); ++i) out[i - s] = v[i];
    return out;
  }

  // The 32-byte ADRS of FIPS 205 Section 4.2.
  Bits adrs(uint32_t layer, const Bits& tree, uint32_t type, const Bits& kp,
            const Bits& ch, const Bits& ix) {
    Bits out;
    append_be(out, c.number(layer, 32), 4);
    append_be(out, tree, 12);
    append_be(out, c.number(type, 32), 4);
    append_be(out, kp, 4);
    append_be(out, ch, 4);
    append_be(out, ix, 4);
    return out;
  }

  // F, H, T_l: SHAKE256(PK.seed || ADRS || data, 8n).
  Bits thash(const Bits& seed, const Bits& a, const Bits& data) {
    Bits in = seed;
    Circuit<E>::append(in, a);
    Circuit<E>::append(in, data);
    return c.shake(in, SLH_N);
  }

  // (left || right) = (node || sib) when bit is 0, (sib || node) when 1.
  Bits ordered(const Bit& bit, const Bits& node, const Bits& sib) {
    Bits out = c.select(bit, sib, node);
    for (size_t i = 0; i < node.size(); ++i)
      out.push_back(e.add(e.add(out[i], node[i]), sib[i]));
    return out;
  }

  // x < c for a constant c, folding the constant prefix.
  Bit less_const(const Bits& x, uint64_t k) {
    std::optional<unsigned> konst = 0u;
    Bit lt = e.constant(0);
    for (size_t i = 0; i < x.size(); ++i) {
      const Bit nx = c.invert(x[i]);
      const bool one = (k >> i) & 1;
      if (!konst) {
        // !x OR lt = !x + lt + !x lt;  !x AND lt = !x lt.
        const Bit both = e.mul(nx, lt);
        lt = one ? e.add(e.add(nx, lt), both) : both;
      } else if (one) {
        if (*konst == 0) {
          lt = nx;
          konst.reset();
        }
      } else if (*konst == 1) {
        lt = nx;
        konst.reset();
      }
    }
    return konst ? e.constant(*konst) : lt;
  }

  // a + b, one bit wider; one multiplication per bit.
  Bits add_grow(const Bits& a, const Bits& b) {
    Bits out(a.size() + 1);
    Bit carry = e.constant(0);
    for (size_t i = 0; i < a.size(); ++i) {
      out[i] = e.add(e.add(a[i], b[i]), carry);
      if (i == 0)
        carry = e.mul(a[0], b[0]);
      else
        carry = e.add(e.mul(e.add(a[i], carry), e.add(b[i], carry)), carry);
    }
    out[a.size()] = carry;
    return out;
  }

  // Pairwise sums, widening by one bit per level.
  Bits sum_tree(std::vector<Bits> v) {
    while (v.size() > 1) {
      std::vector<Bits> next;
      for (size_t i = 0; i + 1 < v.size(); i += 2) next.push_back(add_grow(v[i], v[i + 1]));
      if (v.size() % 2) {
        Bits last = v.back();
        last.push_back(e.constant(0));
        next.push_back(last);
      }
      v = std::move(next);
    }
    return v[0];
  }

  void statement(const SlhStatement& pub) {
    if (!slh_params_ok(&p)) throw std::invalid_argument("SLH-DSA parameters");
    const size_t n8 = 8 * SLH_N;
    auto r = c.input(kSlhROffset, HM_R_BYTES), a = c.input(kSlhAOffset, HM_A_BYTES);
    auto m = c.constant(pub.message), seed = c.constant(pub.pk_seed);

    // m_hat_k = b_k + sum_i a_{k,i} r_i in GF(2^128).
    Bits b;
    for (size_t line = 0; line < 2; ++line) {
      auto sum = e.product(e.pack(Circuit<E>::slice(a, line * 768, 128)),
                           e.pack(Circuit<E>::slice(r, 0, 128)));
      for (size_t i = 1; i < 6; ++i)
        sum = sum + e.product(e.pack(Circuit<E>::slice(a, line * 768 + i * 128, 128)),
                              e.pack(Circuit<E>::slice(r, i * 128, 128)));
      Circuit<E>::append(b, e.field_witness(sum + e.pack(Circuit<E>::slice(m, line * 128, 128))));
    }
    uint64_t nonce_state[25], digest_state[25];
    slh_tag_state(SLH_TAG_NONCE, nonce_state);
    slh_tag_state(SLH_TAG_DIGEST, digest_state);
    const Bits y = shake_from(nonce_state, r, HM_Y_BYTES);
    Bits com = a;
    Circuit<E>::append(com, b);
    Circuit<E>::append(com, y);
    const Bits d = shake_from(digest_state, com, 32);

    const Bits sig = c.input(kSlhSigOffset, slh_detail::sig_bytes(p));
    size_t off = 0;
    auto node = [&] {
      Bits x = Circuit<E>::slice(sig, off, n8);
      off += n8;
      return x;
    };
    const Bits R = node();

    // H_msg = SHAKE256(R || PK.seed || PK.root || 0x00 || 0x00 || d, 8m).
    Bits in = R;
    Circuit<E>::append(in, seed);
    Circuit<E>::append(in, c.constant(pub.pk_root));
    Circuit<E>::append(in, c.number(0, 16));
    Circuit<E>::append(in, d);
    const Bits digest = c.shake(in, p.m);
    const size_t md = slh_md_bytes(&p), tb = slh_tree_bytes(&p), lb = slh_leaf_bytes(&p);
    Bits tree = be_int(digest, md, tb, p.h - p.hp);
    tree.resize(64, e.constant(0));
    Bits leaf = be_int(digest, md + tb, lb, p.hp);
    leaf.resize(32, e.constant(0));
    const Bits zero32 = c.number(0, 32);

    // Algorithm 17.
    Bits roots;
    for (uint32_t i = 0; i < p.k; ++i) {
      const Bits sk = node();
      const Bits idx = stream_int(digest, p.a * i, p.a);
      Bits leaf_index = c.number(uint64_t{i} << p.a, 32);
      for (size_t j = 0; j < p.a; ++j) leaf_index[j] = idx[j];
      Bits cur = thash(seed, adrs(0, tree, 3, leaf, zero32, leaf_index), sk);
      for (uint32_t j = 0; j < p.a; ++j) {
        const Bits sib = node();
        cur = thash(seed, adrs(0, tree, 3, leaf, c.number(j + 1, 32), shr(leaf_index, j + 1)),
                    ordered(idx[j], cur, sib));
      }
      Circuit<E>::append(roots, cur);
    }
    Bits cur = thash(seed, adrs(0, tree, 4, leaf, zero32, zero32), roots);

    // Algorithm 13, one XMSS layer at a time.
    const size_t w = slh_detail::w(p), l1 = slh_len1(&p), l2 = slh_len2(&p);
    for (uint32_t layer = 0; layer < p.d; ++layer) {
      if (layer > 0) {
        leaf = Bits(tree.begin(), tree.begin() + p.hp);
        leaf.resize(32, e.constant(0));
        tree = shr(tree, p.hp);
      }
      // Algorithm 8: base-w digits and the checksum digits.
      std::vector<Bits> digits, terms;
      for (size_t i = 0; i < l1; ++i) {
        digits.push_back(stream_int(cur, p.lg_w * i, p.lg_w));
        Bits t;
        for (const Bit& x : digits.back()) t.push_back(c.invert(x));  // w - 1 - digit
        terms.push_back(t);
      }
      const Bits csum = sum_tree(terms);
      const size_t cbits = 8 * slh_csum_bytes(&p), shift = slh_csum_shift(&p);
      for (size_t t = 0; t < l2; ++t) {
        Bits dg;
        for (size_t j = 0; j < p.lg_w; ++j) {
          const size_t bit = cbits - (t + 1) * p.lg_w + j;  // of csum << shift
          dg.push_back(bit >= shift && bit - shift < csum.size() ? csum[bit - shift]
                                                                 : e.constant(0));
        }
        digits.push_back(dg);
      }
      Bits ends;
      for (uint32_t i = 0; i < l1 + l2; ++i) {
        Bits x = node();
        for (uint32_t s = 0; s + 1 < w; ++s) {
          const Bits y_s =
              thash(seed, adrs(layer, tree, 0, leaf, c.number(i, 32), c.number(s, 32)), x);
          const Bit keep = less_const(digits[i], s + 1);  // digit <= s
          x = c.select(keep, y_s, x);
        }
        Circuit<E>::append(ends, x);
      }
      cur = thash(seed, adrs(layer, tree, 1, leaf, zero32, zero32), ends);
      // Algorithm 11, lines 7-16.
      for (uint32_t k = 0; k < p.hp; ++k) {
        const Bits sib = node();
        cur = thash(seed, adrs(layer, tree, 2, zero32, c.number(k + 1, 32), shr(leaf, k + 1)),
                    ordered(leaf[k], cur, sib));
      }
    }
    if (off != sig.size()) throw std::logic_error("SLH-DSA signature layout");
    c.equal_field(cur, c.constant(pub.pk_root));
    // The VOLE API consumes whole bytes. Bind the final padding bits too.
    while (e.cursor % 8) e.zero(e.allocate(0));
  }
};

}  // namespace voleith
