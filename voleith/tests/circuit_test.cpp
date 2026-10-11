#include "proof.hpp"
#include <iostream>
using namespace voleith;

static void require(bool ok, const char* text) {
  if (!ok) throw std::runtime_error(text);
}

static Bytes primary_for(const uint8_t r[96], const uint8_t a[192],
                         const uint8_t com[256], const uint8_t seed[16],
                         const xmss_sig& sig) {
  Bytes p(kPrimaryBytes);
  memcpy(p.data(), r, 96);
  memcpy(p.data() + 96, a, 192);
  xmss_write_sig(&sig, p.data() + kSigOffset);
  uint8_t d[32], digest[32], coords[42];
  hm_digest(com, d);
  xmss_hash_message(seed, sig.leaf_index, sig.nonce, 24, d, 32, digest);
  require(xmss_extract_coords(digest, coords), "coordinates");
  size_t at = kScheduleOffset;
  for (size_t i = 0; i < 42; ++i)
    for (size_t j = coords[i]; j < 7; ++j) p[at++] = i;
  require(at == kEndpointsOffset, "schedule count");
  xmss_wots_pk_from_sig(
      seed, sig.leaf_index, sig.sig_hashes, coords,
      reinterpret_cast<xmss_node*>(p.data() + kEndpointsOffset));
  return p;
}

int main() try {
  // Linearity makes the basis-vector check exhaustive.
  for (size_t basis = 0; basis < 1600; ++basis) {
    std::array<uint8_t, 1600> state{};
    state[basis] = 1;
    std::array<uint8_t, 320> parity{};
    for (size_t x = 0; x < 5; ++x)
      for (size_t z = 0; z < 64; ++z)
        for (size_t y = 0; y < 5; ++y)
          parity[x * 64 + z] ^= state[(y * 5 + x) * 64 + z];
    for (size_t x = 0; x < 5; ++x)
      for (size_t z = 0; z < 64; ++z)
        for (size_t y = 0; y < 5; ++y)
          state[(y * 5 + x) * 64 + z] ^=
              parity[((x + 4) % 5) * 64 + z] ^
              parity[((x + 1) % 5) * 64 + (z + 63) % 64];
    inverse_theta(state.data(),
                  [](uint8_t a, uint8_t b) { return uint8_t(a ^ b); });
    for (size_t i = 0; i < 1600; ++i)
      require(state[i] == (i == basis), "sparse inverse theta");
  }
  for (size_t index = 0; index < 64; ++index) {
    NativeContext e{Bytes(kPrimaryBytes)};
    Circuit c(e);
    auto flags = c.chain_flags(c.number(index, 8));
    require(flags.size() == 42, "decoder width");
    for (size_t i = 0; i < 42; ++i)
      require(flags[i] == (i == index), "chain index decoder");
  }
  // Compare independent SHAKE implementations at padding boundaries.
  for (size_t n : {size_t(0), 1ul, 135ul, 136ul, 137ul, 272ul, 693ul}) {
    Bytes data(n);
    for (size_t i = 0; i < n; ++i) data[i] = i * 71 + 3;
    NativeContext e(Bytes(kPrimaryBytes), false);
    Circuit c(e);
    auto out = c.shake(c.constant(data), 32);
    uint8_t actual[32]{}, expected[32];
    for (size_t i = 0; i < 256; ++i) actual[i / 8] |= out[i] << (i % 8);
    shake256_raw(data.data(), data.size(), expected, 32);
    require(memcmp(actual, expected, 32) == 0, "PoMFRIT/XKCP SHAKE mismatch");
  }
  Statement s{};
  uint8_t sk[32]{}, r[96]{}, a[192]{}, com[256], d[32];
  for (size_t i = 0; i < 32; ++i) sk[i] = i + 1;
  for (size_t i = 0; i < 16; ++i) s.pk_seed[i] = i + 17;
  for (size_t i = 0; i < 96; ++i) r[i] = i * 7 + 11;
  for (size_t i = 0; i < 192; ++i) a[i] = i * 13 + 3;
  shake256_raw(reinterpret_cast<const uint8_t*>("test message"), 12,
               s.message.data(), 32);
  hm_commit(s.message.data(), r, a, com, d);
  auto tree = xmss_keypair_new(sk, s.pk_seed.data(), 2);
  require(tree, "XMSS keygen");
  xmss_keypair_root(tree, s.root.data());
  xmss_sig sig{};
  require(xmss_keypair_sign(tree, 1, d, 32, &sig), "XMSS sign");
  require(xmss_verify(s.pk_seed.data(), s.root.data(), d, 32, &sig),
          "XMSS verify");
  auto p = primary_for(r, a, com, s.pk_seed.data(), sig);
  NativeContext e(p);
  Circuit c(e);
  c.statement(s);
  require(e.cursor == kWitnessBits && e.constraints == kConstraints &&
              e.permutations == kPermutations,
          "fixed circuit dimensions");
  std::cout << "witness bits=" << e.cursor << " bytes=" << e.witness.size()
            << " constraints=" << e.constraints
            << " permutations=" << e.permutations << '\n';
  using QS = quicksilver_state<secpar::s128, false, kProofDegree>;
  Bytes extended = e.witness;
  extended.resize(extended.size() + kProofDegree * 16);
  std::vector<block128> macs(extended.size() * 8, block128::set_zero());
  uint8_t challenge[56]{};
  QS qs(extended.data(), macs.data(), e.constraints, challenge);
  AuthContext<false> auth(qs);
  Circuit ac(auth);
  ac.statement(s);
  require(auth.cursor == e.cursor && auth.constraints == e.constraints,
          "circuit shape mismatch");
  std::cout << "Authenticated constraints evaluated\n";
  xmss_keypair_free(tree);
  return 0;
} catch (const std::exception& ex) {
  std::cerr << ex.what() << '\n';
  return 1;
}
