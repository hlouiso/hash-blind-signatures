/* Public inputs are m_hat, pk_seed, XMSS root, and the Merkle-prefix
 * midstate (a function of pk_seed). The witness opens the Halevi–Micali
 * commitment and contains a target-sum WOTS+/XMSS signature on
 * d = SHA256(a || b || y) at a secret leaf index. */

#ifndef BLIND_LONGFELLOW_CIRCUIT_BLIND_STMT_H_
#define BLIND_LONGFELLOW_CIRCUIT_BLIND_STMT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "util/panic.h"

#include "commitment.h"
#include "field.h"
#include "sha.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {

constexpr size_t kYBytes = kHashBytes;
constexpr size_t kRBytes = kNNonce * kFeBytes;
constexpr size_t kDomainParamLen = kPkSeedBytes;
constexpr size_t kTargetSum = 195;
static_assert(kTargetSum == xmss_wots_spec().target_sum,
              "circuit target sum drifted from the native spec");

constexpr size_t kCoordBits = xmss_wots_spec().coordinate_resolution_bits;
constexpr size_t kMsgHashBytes = xmss_wots_spec().message_hash_len;
constexpr size_t kBits128 = 128;

constexpr size_t kPooledChainLen = kLen * (kW - 1) - kTargetSum;

constexpr size_t sha_blocks(size_t len) { return (len + 9 + 63) / 64; }

constexpr size_t kRevealLen = kRBytes;
constexpr size_t kRevealBlocks = sha_blocks(kRevealLen);
constexpr size_t kComLen = kComBytes;
constexpr size_t kComBlocks = sha_blocks(kComLen);
constexpr size_t kMsgLen = kDomainParamLen + 1 + kEpochBytes + kNonceLength + 32;
constexpr size_t kMsgBlocks = sha_blocks(kMsgLen);
constexpr size_t kChainLen = kDomainParamLen + 1 + kEpochBytes + kNodeBytes + 1 + 1;
constexpr size_t kChainBlocks = sha_blocks(kChainLen);
constexpr size_t kLtreeLen = kDomainParamLen + 1 + kEpochBytes + kLen * kNodeBytes;
constexpr size_t kLtreeBlocks = sha_blocks(kLtreeLen);

constexpr size_t kTreeIndexBytes = 4;
constexpr size_t kTreeTailLen = 1 + kTreeIndexBytes + kNodeBytes + kNodeBytes;
constexpr size_t kTreeLen = kTreePrefixBytes + kTreeTailLen;
constexpr size_t kTreeTotalBlocks = sha_blocks(kTreeLen);
constexpr size_t kTreeBlocks = 1;
static_assert(kTreeTailLen + 9 <= 64,
              "the tree tail must leave room for its own padding, or the "
              "hoisted prefix buys nothing");
static_assert(kTreeTotalBlocks == kTreeBlocks + 1, "one block is hoisted");

template <class LC>
using StmtFlatSha =
    proofs::FlatSHA256Circuit<LC, proofs::BitPlucker<LC, kPluckerSize>>;
template <class LC>
using StmtBW = typename StmtFlatSha<LC>::BlockWitness;

template <class LC>
struct CommitWires {
  using EltW = typename LC::EltW;
  using v8 = typename LC::v8;
  using v256 = typename LC::v256;
  using BW = StmtBW<LC>;

  std::array<v8, kYBytes> mhat;

  std::array<std::array<v8, kFeBytes>, kNNonce> r_bytes;
  std::array<std::array<std::array<v8, kFeBytes>, kNNonce>, kNLines> a_bytes;
  std::array<std::array<v8, kFeBytes>, kNLines> b_bytes;
  std::array<BW, kRevealBlocks> reveal_bw;
  std::array<BW, kComBlocks> com_bw;
};

template <class LC>
struct SharedXmssWires {
  using v8 = typename LC::v8;
  using v32 = typename LC::v32;
  std::array<v8, kDomainParamLen> domain_param;

  std::array<v32, 8> merkle_midstate;
};

template <class LC>
struct XmssWires {
  using v8 = typename LC::v8;
  using NodeW = typename LC::template bitvec<kNodeBits>;
  using BW = StmtBW<LC>;

  NodeW xmss_root;

  std::array<v8, kNonceLength> nonce;
  std::array<BW, kMsgBlocks> msg_bw;

  std::array<NodeW, kLen> sig_hash;
  std::array<NodeW, kLen> pk_hash;
  std::array<NodeW, kPooledChainLen> step_in;
  std::array<v8, kPooledChainLen> step_chain_idx;
  std::array<v8, kPooledChainLen> step_count;
  std::array<v8, kPooledChainLen> step_position;
  std::array<std::array<BW, kChainBlocks>, kPooledChainLen> step_bw;

  std::array<BW, kLtreeBlocks> leaf_bw;
  std::array<NodeW, kXmssH> auth;
  std::array<std::array<BW, kTreeBlocks>, kXmssH> merkle_bw;
};

template <class LC>
struct StatementWires {
  using v32 = typename LC::v32;
  using FlatSha = StmtFlatSha<LC>;
  using BW = StmtBW<LC>;

  CommitWires<LC> commit;
  SharedXmssWires<LC> shared;
  XmssWires<LC> xmss;
  v32 leaf_index;
};

template <class LC>
typename LC::v8 state_byte(const LC& L, const typename LC::v256& st, size_t p) {
  typename LC::v8 byte;
  for (size_t k = 0; k < 8; ++k) byte[k] = st[8 * (31 - p) + k];
  return byte;
}

template <class LC>
typename LC::template bitvec<kNodeBits> digest_to_node(
    const LC& L, const typename LC::v256& d) {
  return L.template slice<256 - kNodeBits, 256>(d);
}

template <class LC>
typename LC::v8 node_byte(
    const LC& L, const typename LC::template bitvec<kNodeBits>& nd, size_t p) {
  typename LC::v8 byte;
  for (size_t k = 0; k < 8; ++k)
    byte[k] = nd[8 * (kNodeBytes - 1 - p) + k];
  return byte;
}

template <class LC>
typename LC::v8 epoch_byte(const LC& L, const typename LC::v32& epoch, size_t b) {
  typename LC::v8 byte;
  for (size_t k = 0; k < 8; ++k) byte[k] = epoch[8 * b + k];
  return byte;
}

template <class LC>
typename LC::EltW eltw_of_bits(const LC& L, const typename LC::BitW bits[],
                               const Elt pow_x[]) {
  using EltW = typename LC::EltW;
  EltW acc = L.konst(L.zero());
  for (size_t j = 0; j < kBits128; ++j) {
    acc = L.add(acc, L.lmul(bits[j], L.konst(pow_x[j])));
  }
  return acc;
}

template <class LC>
std::array<typename LC::EltW, kNodeFieldLimbs> node_elts_of_bits(
    const LC& L, const typename LC::template bitvec<kNodeBits>& bits,
    const Elt pow_x[]) {
  using EltW = typename LC::EltW;
  std::array<EltW, kNodeFieldLimbs> out;
  for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb) {
    EltW acc = L.konst(L.zero());
    for (size_t j = 0; j < kBits128; ++j) {
      const size_t bit = limb * kBits128 + j;
      if (bit < kNodeBits)
        acc = L.add(acc, L.lmul(bits[bit], L.konst(pow_x[j])));
    }
    out[limb] = acc;
  }
  return out;
}

template <class LC>
typename LC::EltW eltw_of_byte_wires(const LC& L, const typename LC::v8 bytes[],
                                     const Elt pow_x[]) {
  typename LC::BitW bits[kBits128];
  for (size_t B = 0; B < kFeBytes; ++B)
    for (size_t k = 0; k < 8; ++k) bits[8 * B + k] = bytes[B][k];
  return eltw_of_bits(L, bits, pow_x);
}

template <class LC, class FlatSha>
typename LC::v256 digest_of(const LC& L, const FlatSha& sha,
                            const typename FlatSha::BlockWitness& bw) {
  typename LC::v256 mm;
  for (size_t j = 0; j < 8; ++j) {
    const auto hj = sha.bp_.unpack_v32(bw.h1[j]);
    for (size_t k = 0; k < 32; ++k) mm[(7 - j) * 32 + k] = hj[k];
  }
  return mm;
}

template <class LC, class FlatSha>
typename LC::v256 assert_sha(const LC& L, const FlatSha& sha,
                             const std::vector<typename LC::v8>& msg,
                             size_t msg_len, size_t blocks,
                             const typename FlatSha::BlockWitness* bw) {
  using v8 = typename LC::v8;
  std::vector<v8> in(64 * blocks);
  for (size_t i = 0; i < msg_len; ++i) in[i] = msg[i];
  in[msg_len] = L.template vbit<8>(0x80);
  for (size_t i = msg_len + 1; i < 64 * blocks; ++i) in[i] = L.template vbit<8>(0);
  const uint64_t bitlen = static_cast<uint64_t>(msg_len) * 8;
  for (size_t k = 0; k < 8; ++k) {
    in[64 * blocks - 1 - k] = L.template vbit<8>((bitlen >> (8 * k)) & 0xff);
  }
  auto nb = L.template vbit<8>(blocks);
  sha.assert_message(blocks, nb, in.data(), bw);

  return digest_of(L, sha, bw[blocks - 1]);
}

template <class LC, class FlatSha>
typename LC::v256 assert_sha_tail(
    const LC& L, const FlatSha& sha,
    const std::array<typename LC::v32, 8>& midstate,
    const std::vector<typename LC::v8>& msg, size_t msg_len, size_t total_len,
    const typename FlatSha::BlockWitness* bw) {
  using v8 = typename LC::v8;
  using v32 = typename LC::v32;
  proofs::check(msg_len + 9 <= 64, "assert_sha_tail: tail overflows its block");

  std::array<v8, 64> in;
  for (size_t i = 0; i < msg_len; ++i) in[i] = msg[i];
  in[msg_len] = L.template vbit<8>(0x80);
  for (size_t i = msg_len + 1; i < 64; ++i) in[i] = L.template vbit<8>(0);
  const uint64_t bitlen = static_cast<uint64_t>(total_len) * 8;
  for (size_t k = 0; k < 8; ++k) {
    in[63 - k] = L.template vbit<8>((bitlen >> (8 * k)) & 0xff);
  }

  v32 w[16];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = L.vappend(L.vappend(in[4 * i + 3], in[4 * i + 2]),
                     L.vappend(in[4 * i + 1], in[4 * i + 0]));
  }
  sha.assert_transform_block(w, midstate.data(), bw[0].outw, bw[0].oute,
                             bw[0].outa, bw[0].h1);
  return digest_of(L, sha, bw[0]);
}

template <class LC>
typename LC::v256 assert_commit(const LC& L, const CommitWires<LC>& W,
                                const Elt pow_x[]) {
  using v8 = typename LC::v8;
  using v256 = typename LC::v256;
  using EltW = typename LC::EltW;
  const StmtFlatSha<LC> sha(L);

  v256 com_y;
  {
    std::vector<v8> msg(kRevealLen);
    size_t o = 0;
    for (size_t i = 0; i < kNNonce; ++i)
      for (size_t j = 0; j < kFeBytes; ++j) msg[o++] = W.r_bytes[i][j];
    com_y = assert_sha(L, sha, msg, kRevealLen, kRevealBlocks,
                       W.reveal_bw.data());
  }

  {
    std::array<EltW, kNNonce> r_elt;
    for (size_t i = 0; i < kNNonce; ++i)
      r_elt[i] = eltw_of_byte_wires(L, W.r_bytes[i].data(), pow_x);
    for (size_t k = 0; k < kNLines; ++k) {
      EltW acc = eltw_of_byte_wires(L, W.mhat.data() + k * kFeBytes, pow_x);
      for (size_t i = 0; i < kNNonce; ++i) {
        acc = L.add(acc, L.mul(eltw_of_byte_wires(L, W.a_bytes[k][i].data(),
                                                  pow_x),
                               r_elt[i]));
      }
      L.assert0(
          L.add(acc, eltw_of_byte_wires(L, W.b_bytes[k].data(), pow_x)));
    }
  }

  std::vector<v8> msg(kComLen);
  size_t o = 0;
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i)
      for (size_t j = 0; j < kFeBytes; ++j) msg[o++] = W.a_bytes[k][i][j];
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t j = 0; j < kFeBytes; ++j) msg[o++] = W.b_bytes[k][j];
  for (size_t p = 0; p < kYBytes; ++p) msg[o++] = state_byte(L, com_y, p);
  const v256 com_d = assert_sha(L, sha, msg, kComLen, kComBlocks,
                                W.com_bw.data());
  return v256(com_d);
}

template <class LC>
void assert_xmss(const LC& L, const SharedXmssWires<LC>& S,
                 const typename LC::v256& signed_msg,
                 const typename LC::v32& epoch, const XmssWires<LC>& W,
                 const Elt pow_x[]) {
  using v8 = typename LC::v8;
  using v32 = typename LC::v32;
  using v256 = typename LC::v256;
  using NodeW = typename LC::template bitvec<kNodeBits>;
  using BitW = typename LC::BitW;
  const StmtFlatSha<LC> sha(L);

  static_assert(kXmssH == 32, "the epoch is exactly the bits the tree addresses");

  v256 message_hash;
  {
    std::vector<v8> msg(kMsgLen);
    size_t o = 0;
    for (size_t j = 0; j < kDomainParamLen; ++j) msg[o++] = S.domain_param[j];
    msg[o++] = L.template vbit<8>(kMessageTweak);
    for (size_t b = 0; b < kEpochBytes; ++b) msg[o++] = epoch_byte(L, epoch, b);
    for (size_t j = 0; j < kNonceLength; ++j) msg[o++] = W.nonce[j];
    for (size_t p = 0; p < kYBytes; ++p) msg[o++] = state_byte(L, signed_msg, p);
    message_hash = assert_sha(L, sha, msg, kMsgLen, kMsgBlocks, W.msg_bw.data());
  }

  std::array<v8, kLen> coords;
  {
    const auto digest_bit = [&](size_t j) {
      return state_byte(L, message_hash, j / 8)[j % 8];
    };
    typename LC::template bitvec<16> sum = L.template vbit<16>(0);
    for (size_t i = 0; i < kLen; ++i) {
      const size_t pos = coord_bit_pos(i);
      v8 c;
      for (size_t k = 0; k < kCoordBits; ++k) c[k] = digest_bit(pos + k);
      for (size_t k = kCoordBits; k < 8; ++k) c[k] = L.bit(0);
      coords[i] = c;
      typename LC::template bitvec<16> c16 = L.template vbit<16>(0);
      for (size_t k = 0; k < kCoordBits; ++k) c16[k] = c[k];
      sum = L.template vadd<16>(sum, c16);
    }
    L.template vassert_eq<16>(sum, kTargetSum);

    L.assert1(L.lnot(digest_bit(63)));
    L.assert1(L.lnot(digest_bit(8 * kMsgHashBytes - 1)));
  }

  {
    constexpr uint64_t kLm1 = kW - 1;
    using EltW = typename LC::EltW;
    using NodeElts = std::array<EltW, kNodeFieldLimbs>;

    std::array<NodeElts, kLen> pk_elt, sig_elt;
    for (size_t c = 0; c < kLen; ++c) {
      pk_elt[c] = node_elts_of_bits(L, W.pk_hash[c], pow_x);
      sig_elt[c] = node_elts_of_bits(L, W.sig_hash[c], pow_x);
    }

    std::vector<NodeElts> in_elt(kPooledChainLen), out_elt(kPooledChainLen);
    for (size_t j = 0; j < kPooledChainLen; ++j) {
      std::vector<v8> msg(kChainLen);
      size_t o = 0;
      for (size_t k = 0; k < kDomainParamLen; ++k) msg[o++] = S.domain_param[k];
      msg[o++] = L.template vbit<8>(kChainTweak);
      for (size_t b = 0; b < kEpochBytes; ++b) msg[o++] = epoch_byte(L, epoch, b);
      for (size_t p = 0; p < kNodeBytes; ++p) msg[o++] = node_byte(L, W.step_in[j], p);
      msg[o++] = W.step_chain_idx[j];
      msg[o++] = W.step_position[j];
      const NodeW step_out = digest_to_node(
          L, assert_sha(L, sha, msg, kChainLen, kChainBlocks, W.step_bw[j].data()));
      in_elt[j] = node_elts_of_bits(L, W.step_in[j], pow_x);
      out_elt[j] = node_elts_of_bits(L, step_out, pow_x);
    }

    std::vector<std::array<BitW, kLen>> onehot(kPooledChainLen);
    for (size_t j = 0; j < kPooledChainLen; ++j) {
      for (size_t c = 0; c < kLen; ++c) {
        onehot[j][c] =
            L.template veq<8>(W.step_chain_idx[j], static_cast<uint64_t>(c));
      }
      L.assert1(
          L.lor_exclusive(0, kLen, [&](size_t c) { return onehot[j][c]; }));
    }

    std::array<BitW, kPooledChainLen> same;
    std::array<BitW, kPooledChainLen> is_last;
    for (size_t j = 1; j < kPooledChainLen; ++j) {
      same[j] = L.template veq<8>(W.step_chain_idx[j], W.step_chain_idx[j - 1]);
      is_last[j - 1] = L.lnot(same[j]);
    }
    is_last[kPooledChainLen - 1] = L.bit(1);

    for (size_t j = 0; j < kPooledChainLen; ++j) {

      NodeElts sel_sig, sel_pk;
      for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb) {
        sel_sig[limb] = L.add(0, kLen, [&](size_t c) {
          return L.lmul(onehot[j][c], sig_elt[c][limb]);
        });
        sel_pk[limb] = L.add(0, kLen, [&](size_t c) {
          return L.lmul(onehot[j][c], pk_elt[c][limb]);
        });
      }
      v8 sel_coord;
      for (size_t b = 0; b < kCoordBits; ++b) {
        sel_coord[b] = L.lor_exclusive(
            0, kLen, [&](size_t c) { return L.land(onehot[j][c], coords[c][b]); });
      }
      for (size_t b = kCoordBits; b < 8; ++b) sel_coord[b] = L.bit(0);

      L.assert1(L.template veq<8>(
          W.step_position[j], L.template vadd<8>(W.step_count[j], sel_coord)));

      const BitW is_start = L.template veq<8>(W.step_count[j], uint64_t{1});
      for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb)
        L.assert0(L.lmul(is_start, L.add(in_elt[j][limb], sel_sig[limb])));

      for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb)
        L.assert0(L.lmul(is_last[j], L.add(out_elt[j][limb], sel_pk[limb])));
      v8 want_count;
      for (size_t b = 0; b < kCoordBits; ++b) want_count[b] = L.lnot(sel_coord[b]);
      for (size_t b = kCoordBits; b < 8; ++b) want_count[b] = L.bit(0);
      L.assert_implies(is_last[j],
                       L.template veq<8>(W.step_count[j], want_count));

      if (j > 0) {
        const BitW inc_ok = L.template veq<8>(
            W.step_count[j], L.template vadd<8>(W.step_count[j - 1], uint64_t{1}));
        L.assert_implies(same[j], inc_ok);
        for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb)
          L.assert0(L.lmul(same[j],
                           L.add(in_elt[j][limb], out_elt[j - 1][limb])));
        L.assert_implies(L.lnot(same[j]), is_start);
      }
    }
    L.assert1(L.template veq<8>(W.step_count[0], uint64_t{1}));

    for (size_t c = 0; c < kLen; ++c) {
      const BitW is_zero = L.template veq<8>(coords[c], kLm1);
      const BitW covered = L.lor(0, kPooledChainLen, [&](size_t j) {
        return L.land(onehot[j][c], is_last[j]);
      });
      L.assert1(L.lor(covered, is_zero));
      for (size_t limb = 0; limb < kNodeFieldLimbs; ++limb)
        L.assert0(L.lmul(is_zero,
                         L.add(pk_elt[c][limb], sig_elt[c][limb])));
    }
  }

  NodeW leaf;
  {
    std::vector<v8> msg(kLtreeLen);
    size_t o = 0;
    for (size_t j = 0; j < kDomainParamLen; ++j) msg[o++] = S.domain_param[j];
    msg[o++] = L.template vbit<8>(kTreeTweak);
    for (size_t b = 0; b < kEpochBytes; ++b) msg[o++] = epoch_byte(L, epoch, b);
    for (size_t i = 0; i < kLen; ++i)
      for (size_t p = 0; p < kNodeBytes; ++p) msg[o++] = node_byte(L, W.pk_hash[i], p);
    leaf = digest_to_node(
        L, assert_sha(L, sha, msg, kLtreeLen, kLtreeBlocks, W.leaf_bw.data()));
  }

  {
    NodeW current(leaf);
    for (size_t h = 0; h < kXmssH; ++h) {
      const BitW node_is_left = L.lnot(epoch[h]);
      NodeW left, right;
      L.template vmux<kNodeBits>(node_is_left, left, current, W.auth[h]);
      L.template vmux<kNodeBits>(node_is_left, right, W.auth[h], current);

      const v32 node_index = L.template vshr<32>(epoch, h + 1);

      std::vector<v8> msg(kTreeTailLen);
      size_t o = 0;
      msg[o++] = L.template vbit<8>(static_cast<uint64_t>(h) & 0xff);
      for (size_t k = 0; k < kTreeIndexBytes; ++k) {
        v8 byte;
        for (size_t bit = 0; bit < 8; ++bit) byte[bit] = node_index[8 * k + bit];
        msg[o++] = byte;
      }
      for (size_t p = 0; p < kNodeBytes; ++p) msg[o++] = node_byte(L, left, p);
      for (size_t p = 0; p < kNodeBytes; ++p) msg[o++] = node_byte(L, right, p);

      current = digest_to_node(
          L, assert_sha_tail(L, sha, S.merkle_midstate, msg, kTreeTailLen,
                             kTreeLen, W.merkle_bw[h].data()));
    }
    L.template vassert_eq<kNodeBits>(current, W.xmss_root);
  }
}

template <class LC>
void assert_statement(const LC& L, const Field& F, const StatementWires<LC>& W,
                      const Elt pow_x[]) {
  (void)F;
  const typename LC::v256 com_d = assert_commit(L, W.commit, pow_x);
  assert_xmss(L, W.shared, com_d, W.leaf_index, W.xmss, pow_x);
}

inline void fill_pow_x(const Field& F, Elt pow_x[]) {
  pow_x[0] = F.one();
  const Elt x = F.x();
  for (size_t j = 1; j < kBits128; ++j) pow_x[j] = F.mulf(pow_x[j - 1], x);
}

}

#endif
