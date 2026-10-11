#include "proof.hpp"
#include "small_vole.inc"
#include "vole_commit.inc"
#include "vole_check.hpp"
extern "C" {
#include "native/randombytes.h"
}

namespace voleith {
namespace {
// Replace FAEST's AES relation with the XMSS/HM witness and constraints.
struct Params
    : faest::parameter_set<secpar::s128, kVoleTrees, owf::v1, prg::aes_ctr,
                           prg::aes_ctr, leaf_hash::shake, kGrindingBits> {
  struct OWF_CONSTS {
    static constexpr size_t WITNESS_BITS = kWitnessBits;
    static constexpr size_t QS_DEGREE = kProofDegree;
  };

  using CONSTS = faest::CONSTANTS<Params>;
};

using CP = Params::CONSTS;
using VC = Params::bavc_t;
constexpr size_t WBytes = kWitnessBits / 8;
static_assert(!Params::use_crt_vole_masks && VC::OPEN_ALWAYS_SUCCEEDS);
static_assert(CP::VOLE_EXTRA_BYTES == 0 &&
              CP::QS::PROOF_BYTES == (kProofDegree - 1) * 16);

hash_state transcript(uint8_t tag) {
  hash_state h;
  h.init(secpar::s256);  // SHAKE256, also when the VOLE field is GF(2^128).
  constexpr char domain[] = "HBS-VOLE-PROOF-v1";
  h.update(domain, sizeof(domain) - 1);
  h.update(kProofVersion);
  h.update_byte(kVoleTrees);
  h.update_byte(kProofDegree);
  h.update_byte(kGrindingBits);
  h.update_byte(tag);
  return h;
}

block128 get_iv(std::span<const uint8_t> nonce) {
  auto h = transcript(0);
  h.update(nonce);
  block128 iv;
  h.finalize(&iv, sizeof(iv));
  return iv;
}

auto challenge1(const Statement& s, const uint8_t* nonce, const uint8_t* check,
                const uint8_t* commitment, block128 iv) {
  std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> out;
  auto h = transcript(1);
  h.update(s.message);
  h.update(s.pk_seed);
  h.update(s.root);
  h.update(nonce, 32);
  h.update(check, CP::VOLE_COMMIT_CHECK_SIZE);
  h.update(commitment, CP::VOLE_COMMIT_SIZE);
  h.update(&iv, sizeof(iv));
  h.finalize(out);
  return out;
}

auto challenge3_prefix(const uint8_t* chal2, const uint8_t* qs_check,
                       const uint8_t* qs_proof) {
  auto h = transcript(3);
  h.update(chal2, CP::QS::CHALLENGE_BYTES);
  h.update(qs_check, CP::QS::CHECK_BYTES);
  h.update(qs_proof, CP::QS::PROOF_BYTES);
  return h;
}

auto finish_challenge3(hash_state h, const uint8_t* counter) {
  std::array<uint8_t, 16> out;
  if constexpr (kGrindingBits > 0) h.update(counter, 4);
  h.finalize(out);
  return out;
}

bool grinding_passes(const uint8_t* delta) {
  unsigned bad = 0;
  for (size_t bit = 128 - kGrindingBits; bit < 128; ++bit)
    bad |= (delta[bit / 8] >> (bit % 8)) & 1;
  return bad == 0;
}

template <class E>
void evaluate(E& e, const Statement& s) {
  Circuit c(e);
  c.statement(s);
  if (e.cursor != kWitnessBits || e.constraints != kConstraints ||
      e.permutations != kPermutations)
    throw std::logic_error("circuit and VOLE parameters disagree");
}
}

ProofLayout proof_layout() {
  ProofLayout l{};
  l.nonce = kProofVersion.size() + 3;
  l.commitment = l.nonce + 32;
  l.vole_check = l.commitment + CP::VOLE_COMMIT_SIZE;
  l.correction = l.vole_check + CP::VOLE_CHECK::PROOF_BYTES;
  l.quicksilver = l.correction + WBytes;
  l.opening = l.quicksilver + CP::QS::PROOF_BYTES;
  l.delta = l.opening + VC::OPEN_SIZE;
  l.counter = l.delta + 16;
  l.size = l.counter + (kGrindingBits > 0 ? 4 : 0);
  return l;
}

Bytes prove(const Statement& s, const Bytes& primary) {
  if (primary.size() != kPrimaryBytes)
    throw std::invalid_argument("primary witness size");
  NativeContext native(primary);
  evaluate(native, s);
  const auto l = proof_layout();
  Bytes proof(l.size);
  std::copy(kProofVersion.begin(), kProofVersion.end(), proof.begin());
  auto p = proof.data();
  p[8] = kVoleTrees;
  p[9] = kProofDegree;
  p[10] = kGrindingBits;
  block128 seed;
  if (!randombytes_fill(&seed, sizeof(seed)) ||
      !randombytes_fill(p + l.nonce, 32))
    throw std::runtime_error("OS random source failed");
  const auto iv = get_iv({p + l.nonce, 32});
  std::vector<block128> forest(VC::COMMIT_NODES);
  Bytes leaves(VC::COMMIT_LEAVES * Params::leaf_hash_t::hash_len);
  std::vector<vole_block> u(CP::VOLE_COL_BLOCKS), v(128 * CP::VOLE_COL_BLOCKS);
  std::array<uint8_t, CP::VOLE_COMMIT_CHECK_SIZE> check;
  faest::detail::vole_commit_impl<Params>(
      seed, iv, forest.data(), leaves.data(), u.data(), v.data(),
      p + l.commitment, check.data(), nullptr);
  const auto chal1 =
      challenge1(s, p + l.nonce, check.data(), p + l.commitment, iv);
  auto h2 = transcript(2);
  h2.update(chal1);
  vole_check_sender<Params>(u.data(), v.data(), chal1.data(), p + l.vole_check,
                            h2);
  auto u_bytes = reinterpret_cast<uint8_t*>(u.data());
  for (size_t i = 0; i < WBytes; ++i)
    p[l.correction + i] = u_bytes[i] ^ native.witness[i];
  h2.update(p + l.correction, WBytes);
  std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
  h2.finalize(chal2);
  std::vector<block128> macs(CP::QUICKSILVER_ROWS_PADDED);
  transpose_secpar<secpar::s128>(v.data(), macs.data(), CP::VOLE_COL_STRIDE,
                                 CP::QUICKSILVER_ROWS_PADDED);
  // Preserve the independent VOLE masks immediately following the witness.
  memcpy(u_bytes, native.witness.data(), WBytes);
  AuthContext<false>::QS qs(u_bytes, macs.data(), kConstraints, chal2.data());
  AuthContext<false> auth(qs);
  evaluate(auth, s);
  std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
  qs.prove(kWitnessBits, p + l.quicksilver, qs_check.data());
  const auto h3 =
      challenge3_prefix(chal2.data(), qs_check.data(), p + l.quicksilver);
  auto delta = finish_challenge3(h3, p + l.counter);
  if constexpr (kGrindingBits > 0) {
    uint32_t counter = 0;
    while (!grinding_passes(delta.data())) {
      if (counter == UINT32_MAX)
        throw std::runtime_error("Fiat-Shamir grinding counter exhausted");
      ++counter;
      for (size_t i = 0; i < 4; ++i) p[l.counter + i] = counter >> (8 * i);
      delta = finish_challenge3(h3, p + l.counter);
    }
  }
  std::array<uint8_t, 128> expanded;
  expand_bits_to_bytes(expanded.data(), 128, delta.data());
  if (!VC::open(forest.data(), leaves.data(), expanded.data(), p + l.opening))
    throw std::logic_error("GGM forest opening failed");
  memcpy(p + l.delta, delta.data(), delta.size());
  return proof;
}

bool verify(const Statement& s, std::span<const uint8_t> proof) {
  const auto l = proof_layout();
  if (proof.size() != l.size ||
      !std::equal(kProofVersion.begin(), kProofVersion.end(), proof.begin()) ||
      proof[8] != kVoleTrees || proof[9] != kProofDegree ||
      proof[10] != kGrindingBits)
    return false;
  auto p = proof.data();
  if (!grinding_passes(p + l.delta)) return false;
  const auto iv = get_iv({p + l.nonce, 32});
  std::array<uint8_t, 128> expanded;
  expand_bits_to_bytes(expanded.data(), 128, p + l.delta);
  std::vector<vole_block> q(128 * CP::VOLE_COL_BLOCKS);
  std::array<uint8_t, CP::VOLE_COMMIT_CHECK_SIZE> check;
  if (!faest::detail::vole_reconstruct_impl<Params>(
          iv, q.data(), expanded.data(), p + l.commitment, p + l.opening,
          check.data()))
    return false;
  const auto chal1 =
      challenge1(s, p + l.nonce, check.data(), p + l.commitment, iv);
  auto h2 = transcript(2);
  h2.update(chal1);
  // Sender hashes u-tilde as its first column; receiver hashes it explicitly.
  h2.update(p + l.vole_check, CP::VOLE_CHECK::PROOF_BYTES);
  vole_check_receiver<Params>(q.data(), expanded.data(), chal1.data(),
                              p + l.vole_check, h2);
  h2.update(p + l.correction, WBytes);
  std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
  h2.finalize(chal2);
  std::vector<vole_block> correction(CP::WITNESS_BLOCKS,
                                     vole_block::set_zero());
  memcpy(correction.data(), p + l.correction, WBytes);
  vole_receiver_apply_correction<Params>(
      CP::WITNESS_BLOCKS, 128, correction.data(), q.data(), expanded.data());
  std::vector<block128> macs(CP::QUICKSILVER_ROWS_PADDED);
  transpose_secpar<secpar::s128>(q.data(), macs.data(), CP::VOLE_COL_STRIDE,
                                 CP::QUICKSILVER_ROWS_PADDED);
  block128 delta;
  memcpy(&delta, p + l.delta, sizeof(delta));
  AuthContext<true>::QS qs(macs.data(), kConstraints, delta, chal2.data());
  AuthContext<true> auth(qs);
  evaluate(auth, s);
  std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
  qs.verify(kWitnessBits, p + l.quicksilver, qs_check.data());
  const auto expected = finish_challenge3(
      challenge3_prefix(chal2.data(), qs_check.data(), p + l.quicksilver),
      p + l.counter);
  uint8_t different = 0;
  for (size_t i = 0; i < 16; ++i) different |= expected[i] ^ p[l.delta + i];
  return different == 0;
}
}
