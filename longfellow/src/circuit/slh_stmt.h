/* The SLH-DSA blind-signature statement: a Halevi–Micali opening of the
 * public m_hat (with the tagged SHA-256 hashes of slh/commit.h), and a pure
 * SLH-DSA-SHA2 signature (empty context) on d = SHA-256(TAG_DIGEST || a || b
 * || y) under the public key (PK.seed, PK.root). A port of
 * binius64/src/slh/gadget.rs.
 *
 * Public inputs: m_hat, PK.seed, PK.root, and the SHA-256 midstate after
 * PK.seed || 0^48, which the verifier computes from PK.seed. Everything else
 * is witness: r, a, b, the signature (R, FORS, WOTS+, authentication paths)
 * and one block witness per SHA-256 compression, in the order the statement
 * hashes. The digest, indices, addresses and chain digits are computed from
 * the witness, so they stay secret.
 *
 * Every value is a byte of eight Boolean wires: inputs are asserted to be
 * bits, and the bit plucker checks membership in the four-bit SHA-256 encoding. The
 * ADRSc bytes are rewired digest bits, so no carry or high-half garbage can
 * reach them.
 *
 * The WOTS+ chains take all w - 1 steps at hash addresses s = 0 .. w - 2,
 * keeping step s exactly when the digit is at most s, so the circuit does
 * not depend on the digits. */

#ifndef BLIND_LONGFELLOW_CIRCUIT_SLH_STMT_H_
#define BLIND_LONGFELLOW_CIRCUIT_SLH_STMT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuit/blind_stmt.h"
#include "slh/commit.h"
#include "slh/native.h"
#include "slh/params.h"
#include "util/panic.h"

namespace blind_longfellow {
namespace slh {

constexpr size_t kComBodyBytes = kComBytes;   // a || b || y
constexpr size_t kRBodyBytes = kNNonce * kFeBytes;
constexpr size_t kMPrimeBytes = 2 + kHashBytes;  // 0x00 || 0x00 || d

// SHA-256 blocks for `len` bytes that follow a block-aligned prefix.
constexpr size_t sha_blocks_after(size_t len) { return (len + 9 + 63) / 64; }

// SHA-256 compressions the statement checks, in order.
struct SlhShape {
  explicit SlhShape(const SlhParams& p_) : p(p_) {}
  size_t commit() const {
    return sha_blocks_after(kRBodyBytes) + sha_blocks_after(kComBodyBytes);
  }
  size_t hmsg() const {
    return sha_blocks_after(3 * kN + kMPrimeBytes) +
           sha_blocks_after(2 * kN + kHashBytes + 4);
  }
  size_t tk() const { return sha_blocks_after(22 + kN * p.k); }
  size_t tlen() const { return sha_blocks_after(22 + kN * p.len()); }
  size_t fors() const { return p.k * (1 + p.a) + tk(); }
  size_t layer() const { return p.len() * (p.w() - 1) + tlen() + p.hp; }
  size_t total() const { return commit() + hmsg() + fors() + p.d * layer(); }
  const SlhParams p;
};

template <class LC>
struct SlhWires {
  using v8 = typename LC::v8;
  using v32 = typename LC::v32;
  using BW = StmtBW<LC>;

  // Public.
  std::vector<v8> mhat;     // 32 bytes
  std::vector<v8> pk_seed;  // 16 bytes
  std::vector<v8> pk_root;  // 16 bytes
  std::array<v32, 8> mid;   // SHA-256 state after PK.seed || 0^48
  // Private.
  std::vector<v8> r, a, b;  // 96, 192 and 32 bytes
  std::vector<v8> sig;      // the FIPS 205 encoding R || SIG_FORS || SIG_HT
  std::vector<BW> bw;       // every SHA-256 block witness, in call order
};

template <class LC>
class SlhStatement {
 public:
  using v8 = typename LC::v8;
  using v32 = typename LC::v32;
  using BitW = typename LC::BitW;
  using EltW = typename LC::EltW;
  using BW = StmtBW<LC>;
  using Bytes8 = std::vector<v8>;
  using Bits = std::vector<BitW>;  // an integer, least significant bit first

  SlhStatement(const LC& L, const SlhParams& p, const SlhWires<LC>& W,
               const Elt pow_x[])
      : L_(L), p_(p), W_(W), pow_x_(pow_x), sha_(L) {}

  void assert_all() {
    proofs::check(W_.bw.size() == SlhShape(p_).total(),
                  "SlhStatement: block witness count");
    const Bytes8 d = assert_commit();
    assert_slh(d);
    proofs::check(cursor_ == W_.bw.size(),
                  "SlhStatement: unused block witnesses");
  }

 private:
  struct AdrsW {
    uint8_t layer;
    Bits tree;  // 64 bits
    uint8_t type;
    Bits kp, ch, ix;  // 32 bits each
  };

  const BW& next_bw() {
    proofs::check(cursor_ < W_.bw.size(), "SlhStatement: out of block witnesses");
    return W_.bw[cursor_++];
  }

  v8 kbyte(uint64_t x) const { return L_.template vbit<8>(x & 0xff); }

  Bits kbits(uint64_t v, size_t n) const {
    Bits out(n);
    for (size_t i = 0; i < n; ++i) out[i] = L_.bit(i < 64 ? (v >> i) & 1 : 0);
    return out;
  }

  Bits shr(const Bits& v, size_t s) const {
    Bits out(v.size(), L_.bit(0));
    for (size_t i = s; i < v.size(); ++i) out[i - s] = v[i];
    return out;
  }

  Bits widen(Bits v, size_t n) const {
    v.resize(n, L_.bit(0));
    return v;
  }

  static void append(Bytes8& dst, const Bytes8& src) {
    dst.insert(dst.end(), src.begin(), src.end());
  }

  // The low 8 * nbytes bits of v, big-endian.
  void append_be(Bytes8& dst, const Bits& v, size_t nbytes) const {
    for (size_t j = 0; j < nbytes; ++j) {
      v8 byte;
      for (size_t k = 0; k < 8; ++k) {
        const size_t bit = 8 * (nbytes - 1 - j) + k;
        byte[k] = bit < v.size() ? v[bit] : L_.bit(0);
      }
      dst.push_back(byte);
    }
  }

  Bytes8 slice(const Bytes8& x, size_t off, size_t n) const {
    return Bytes8(x.begin() + off, x.begin() + off + n);
  }

  // Bit t of a byte string read as a big-endian bit stream.
  static BitW stream_bit(const Bytes8& x, size_t t) { return x[t / 8][7 - t % 8]; }

  // Bits [start, start + n) of the stream as an integer (Algorithm 4).
  Bits stream_int(const Bytes8& x, size_t start, size_t n) const {
    Bits out(n);
    for (size_t j = 0; j < n; ++j) out[j] = stream_bit(x, start + n - 1 - j);
    return out;
  }

  // The low `bits` bits of x[off, off + nbytes) read as a big-endian integer.
  Bits be_int(const Bytes8& x, size_t off, size_t nbytes, size_t bits) const {
    Bits out(bits);
    for (size_t j = 0; j < bits; ++j)
      out[j] = x[off + nbytes - 1 - j / 8][j % 8];
    return out;
  }

  // SHA-256 of msg, which follows `prefix` bytes already compressed into h0,
  // truncated to out_bytes.
  template <class H0>
  Bytes8 sha(const H0& h0, const Bytes8& msg, size_t prefix, size_t out_bytes) {
    const size_t nb = sha_blocks_after(msg.size());
    Bytes8 in(64 * nb);
    for (size_t i = 0; i < msg.size(); ++i) in[i] = msg[i];
    in[msg.size()] = kbyte(0x80);
    for (size_t i = msg.size() + 1; i < 64 * nb; ++i) in[i] = kbyte(0);
    const uint64_t bitlen = static_cast<uint64_t>(prefix + msg.size()) * 8;
    for (size_t k = 0; k < 8; ++k) in[64 * nb - 1 - k] = kbyte(bitlen >> (8 * k));
    const BW* prev = nullptr;
    for (size_t b = 0; b < nb; ++b) {
      v32 w[16];
      const v8* blk = &in[64 * b];
      for (size_t i = 0; i < 16; ++i)
        w[i] = L_.vappend(L_.vappend(blk[4 * i + 3], blk[4 * i + 2]),
                          L_.vappend(blk[4 * i + 1], blk[4 * i + 0]));
      const BW& bw = next_bw();
      if (prev == nullptr) {
        sha_.assert_transform_block(w, h0.data(), bw.outw, bw.oute, bw.outa,
                                    bw.h1);
      } else {
        sha_.assert_transform_block(w, prev->h1, bw.outw, bw.oute, bw.outa,
                                    bw.h1);
      }
      prev = &bw;
    }
    Bytes8 out(out_bytes);
    for (size_t j = 0; 4 * j < out_bytes; ++j) {
      const v32 hj = sha_.bp_.unpack_v32(prev->h1[j]);
      for (size_t q = 0; q < 4 && 4 * j + q < out_bytes; ++q)
        for (size_t k = 0; k < 8; ++k) out[4 * j + q][k] = hj[8 * (3 - q) + k];
    }
    return out;
  }

  std::array<v32, 8> const_state(const State& st) const {
    std::array<v32, 8> out;
    for (size_t i = 0; i < 8; ++i) out[i] = L_.template vbit<32>(st[i]);
    return out;
  }

  Bytes8 adrsc(const AdrsW& a) const {
    Bytes8 out;
    out.push_back(kbyte(a.layer));
    append_be(out, a.tree, 8);
    out.push_back(kbyte(a.type));
    append_be(out, a.kp, 4);
    append_be(out, a.ch, 4);
    append_be(out, a.ix, 4);
    return out;
  }

  // Trunc_n(SHA-256(PK.seed || 0^48 || ADRSc || data)), from the midstate.
  Bytes8 thash(const AdrsW& a, const Bytes8& data) {
    Bytes8 msg = adrsc(a);
    append(msg, data);
    return sha(W_.mid, msg, 64, kN);
  }

  // (left, right) = (node, sib) when bit is 0, (sib, node) when it is 1.
  Bytes8 ordered(const BitW& bit, const Bytes8& node, const Bytes8& sib) const {
    Bytes8 out(2 * kN);
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        const BitW delta = L_.land(bit, L_.lxor(node[i][j], sib[i][j]));
        out[i][j] = L_.lxor(node[i][j], delta);
        out[kN + i][j] = L_.lxor(sib[i][j], delta);
      }
    }
    return out;
  }

  // x < c for a constant c, comparing from the least significant bit.
  BitW less_const(const Bits& x, uint64_t c) const {
    BitW lt = L_.bit(0);
    for (size_t i = 0; i < x.size(); ++i)
      lt = ((c >> i) & 1) ? L_.lor(L_.lnot(x[i]), lt)
                          : L_.land(L_.lnot(x[i]), lt);
    return lt;
  }

  Bytes8 assert_commit() {
    const std::array<v32, 8> nonce_mid = const_state(tag_midstate(kTagNonce));
    const std::array<v32, 8> digest_mid = const_state(tag_midstate(kTagDigest));
    const Bytes8 y = sha(nonce_mid, W_.r, kTagBytes, kHashBytes);

    // m_hat_k + sum_i a_{k,i} r_i + b_k = 0 in GF(2^128).
    std::array<EltW, kNNonce> r_elt;
    for (size_t i = 0; i < kNNonce; ++i)
      r_elt[i] = eltw_of_byte_wires(L_, &W_.r[i * kFeBytes], pow_x_);
    for (size_t k = 0; k < kNLines; ++k) {
      EltW acc = eltw_of_byte_wires(L_, &W_.mhat[k * kFeBytes], pow_x_);
      for (size_t i = 0; i < kNNonce; ++i)
        acc = L_.add(acc, L_.mul(eltw_of_byte_wires(
                                     L_, &W_.a[(k * kNNonce + i) * kFeBytes],
                                     pow_x_),
                                 r_elt[i]));
      L_.assert0(L_.add(acc, eltw_of_byte_wires(L_, &W_.b[k * kFeBytes], pow_x_)));
    }

    Bytes8 com = W_.a;
    append(com, W_.b);
    append(com, y);
    return sha(digest_mid, com, kTagBytes, kHashBytes);
  }

  void assert_slh(const Bytes8& d) {
    const SlhParams& p = p_;
    proofs::check(p.m <= kHashBytes, "H_msg beyond one MGF1 block");
    size_t off = 0;
    auto node = [&] {
      Bytes8 n = slice(W_.sig, off, kN);
      off += kN;
      return n;
    };
    const Bytes8 R = node();
    const std::array<v32, 8> iv = const_state(kSha256Iv);

    // H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root
    // || M'), m) with M' = 0x00 || 0x00 || d.
    Bytes8 in = R;
    append(in, W_.pk_seed);
    append(in, W_.pk_root);
    in.push_back(kbyte(0));
    in.push_back(kbyte(0));
    append(in, d);
    const Bytes8 inner = sha(iv, in, 0, kHashBytes);
    in = R;
    append(in, W_.pk_seed);
    append(in, inner);
    for (size_t i = 0; i < 4; ++i) in.push_back(kbyte(0));
    const Bytes8 digest = sha(iv, in, 0, p.m);

    // Algorithms 19-20, lines 7-11.
    Bits tree = widen(be_int(digest, p.md_bytes(), p.tree_bytes(), p.tree_bits()), 64);
    Bits leaf = widen(
        be_int(digest, p.md_bytes() + p.tree_bytes(), p.leaf_bytes(), p.hp), 32);

    // Algorithm 17.
    Bytes8 roots;
    for (size_t i = 0; i < p.k; ++i) {
      const Bytes8 sk = node();
      const Bits idx = stream_int(digest, p.a * i, p.a);
      Bits leaf_index = kbits(static_cast<uint64_t>(i) << p.a, 32);
      for (size_t j = 0; j < p.a; ++j) leaf_index[j] = idx[j];
      Bytes8 cur = thash({0, tree, kForsTree, leaf, kbits(0, 32), leaf_index}, sk);
      for (size_t j = 0; j < p.a; ++j) {
        const Bytes8 sib = node();
        cur = thash({0, tree, kForsTree, leaf, kbits(j + 1, 32),
                     shr(leaf_index, j + 1)},
                    ordered(idx[j], cur, sib));
      }
      append(roots, cur);
    }
    Bytes8 cur = thash({0, tree, kForsRoots, leaf, kbits(0, 32), kbits(0, 32)}, roots);

    // Algorithm 13, one XMSS layer at a time.
    const size_t w = p.w();
    for (size_t layer = 0; layer < p.d; ++layer) {
      if (layer > 0) {
        leaf = widen(Bits(tree.begin(), tree.begin() + p.hp), 32);
        tree = shr(tree, p.hp);
      }
      const uint8_t l = static_cast<uint8_t>(layer);

      // Algorithm 8: base-w digits, then the checksum digits.
      std::vector<Bits> digits;
      typename LC::template bitvec<16> csum = L_.template vbit<16>(0);
      for (size_t i = 0; i < p.len1(); ++i) {
        digits.push_back(stream_int(cur, p.lg_w * i, p.lg_w));
        typename LC::template bitvec<16> term = L_.template vbit<16>(0);
        for (size_t j = 0; j < p.lg_w; ++j) term[j] = L_.lnot(digits.back()[j]);
        csum = L_.template vadd<16>(csum, term);
      }
      const size_t cbits = 8 * p.csum_bytes();
      for (size_t t = 0; t < p.len2(); ++t) {
        Bits dg(p.lg_w);
        for (size_t j = 0; j < p.lg_w; ++j) {
          const size_t bit = cbits - (t + 1) * p.lg_w + j;  // of csum << shift
          dg[j] = bit >= p.csum_shift() ? csum[bit - p.csum_shift()] : L_.bit(0);
        }
        digits.push_back(dg);
      }

      Bytes8 ends;
      for (size_t i = 0; i < p.len(); ++i) {
        Bytes8 x = node();
        for (size_t s = 0; s + 1 < w; ++s) {
          const Bytes8 y =
              thash({l, tree, kWotsHash, leaf, kbits(i, 32), kbits(s, 32)}, x);
          const BitW keep = less_const(digits[i], s + 1);  // digit <= s
          for (size_t q = 0; q < kN; ++q) {
            v8 kept;
            L_.vmux(keep, kept, y[q], x[q]);
            x[q] = kept;
          }
        }
        append(ends, x);
      }
      cur = thash({l, tree, kWotsPk, leaf, kbits(0, 32), kbits(0, 32)}, ends);

      // Algorithm 11, lines 7-16.
      for (size_t k = 0; k < p.hp; ++k) {
        const Bytes8 sib = node();
        cur = thash({l, tree, kTree, kbits(0, 32), kbits(k + 1, 32), shr(leaf, k + 1)},
                    ordered(leaf[k], cur, sib));
      }
    }
    proofs::check(off == p.sig_bytes(), "SlhStatement: signature layout");
    for (size_t i = 0; i < kN; ++i) L_.vassert_eq(cur[i], W_.pk_root[i]);
  }

  const LC& L_;
  const SlhParams& p_;
  const SlhWires<LC>& W_;
  const Elt* pow_x_;
  const StmtFlatSha<LC> sha_;
  size_t cursor_ = 0;
};

template <class LC>
void assert_slh_statement(const LC& L, const SlhParams& p,
                          const SlhWires<LC>& W, const Elt pow_x[]) {
  SlhStatement<LC>(L, p, W, pow_x).assert_all();
}

}  // namespace slh
}  // namespace blind_longfellow

#endif
