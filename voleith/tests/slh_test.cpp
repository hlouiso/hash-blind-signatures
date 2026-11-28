// Tests of the SLH-DSA-SHAKE blind signature: the native code against the
// shared vectors of ../test-vectors/slh (written by binius64's slh_kat), the
// commitment tags, the circuit with the native and authenticated engines on
// toy parameters and on SLH-DSA-SHAKE-128-24, and end-to-end VOLEitH proofs.
#include <chrono>
#include <cstdio>
#include <functional>
#include <iostream>
#include <string>

#include "slh_protocol.hpp"
#include "slh_vectors.h"

using namespace voleith;
using testvec::Json;
using testvec::unhex;
using Clock = std::chrono::steady_clock;

namespace {
int passed = 0, failed = 0;

void record(const std::string& name, bool ok) {
  (ok ? passed : failed)++;
  std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
  std::fflush(stdout);
}

double since(Clock::time_point t) {
  return std::chrono::duration<double>(Clock::now() - t).count();
}

std::string vec_path(const char* file) {
  return std::string(SLH_TEST_VECTOR_DIR) + "/" + file;
}

template <class F>
bool throws_invalid(F f) {
  try {
    f();
  } catch (const std::invalid_argument&) {
    return true;
  }
  return false;
}

// ------------------------------------------------------------- primitives

void test_sponge_and_tags() {
  bool same = true;
  for (size_t n : {size_t(0), 1ul, 34ul, 135ul, 136ul, 137ul, 272ul, 1136ul, 1500ul}) {
    Bytes data(n);
    for (size_t i = 0; i < n; ++i) data[i] = uint8_t(i * 71 + 3);
    uint8_t a[200], b[200];
    const uint8_t* parts[1] = {data.data()};
    const size_t lens[1] = {n};
    slh_shake256(parts, lens, 1, a, sizeof(a));
    shake256_raw(data.data(), n, b, sizeof(b));
    same &= memcmp(a, b, sizeof(a)) == 0;
  }
  record("native sponge matches XKCP SHAKE256 at every padding boundary", same);

  // Every tag lies outside the fixed structure of the other SHAKE256 inputs.
  const uint8_t* tags[3] = {SLH_TAG_MESSAGE, SLH_TAG_NONCE, SLH_TAG_DIGEST};
  bool apart = memcmp(tags[0], tags[1], SLH_TAG_BYTES) && memcmp(tags[1], tags[2], SLH_TAG_BYTES) &&
               memcmp(tags[0], tags[2], SLH_TAG_BYTES);
  for (const uint8_t* t : tags) {
    const bool layer = t[16] | t[17] | t[18];            // F, H, T_l, PRF
    const bool tree_top = t[20] | t[21] | t[22] | t[23];  // F, H, T_l, PRF
    const bool hmsg = t[48] | t[49];                      // H_msg, empty context
    const bool prfmsg = t[32] | t[33];                    // PRF_msg
    const bool transcript = memcmp(t, "HBS-VOLE-", 9) != 0;
    const bool prefix = memcmp(t, "blind-", 6) == 0;
    apart &= layer && tree_top && hmsg && prfmsg && transcript && prefix;
    for (size_t i = 38; i < SLH_TAG_BYTES; ++i) apart &= t[i] == 0xff;
  }
  record("tags are distinct and outside the other SHAKE256 domains", apart);

  // The tag state is the state SHAKE256(tag || x) continues from.
  NativeContext e(Bytes(0), false, 0);
  Circuit<NativeContext> c(e);
  Bytes x(100);
  for (size_t i = 0; i < x.size(); ++i) x[i] = uint8_t(5 * i + 1);
  uint64_t st[25];
  slh_tag_state(SLH_TAG_DIGEST, st);
  const auto out = c.shake(c.constant(x), 32, st);
  uint8_t got[32] = {}, want[32];
  for (size_t i = 0; i < 256; ++i) got[i / 8] |= out[i] << (i % 8);
  Bytes cat(SLH_TAG_DIGEST, SLH_TAG_DIGEST + SLH_TAG_BYTES);
  cat.insert(cat.end(), x.begin(), x.end());
  shake256_raw(cat.data(), cat.size(), want, 32);
  record("circuit SHAKE256 after a tag block matches XKCP", memcmp(got, want, 32) == 0);
}

// Compare every possible stopping position with the native SHAKE256 chain.
void test_wots_endpoints(const slh_params& p) {
  NativeContext e({}, true, 0);
  SlhCircuit<NativeContext> slh(e, p);
  const auto zero = slh.c.number(0, 32);
  std::array<uint8_t, SLH_N> seed{}, sig{};
  for (size_t i = 0; i < SLH_N; ++i) {
    seed[i] = static_cast<uint8_t>(i + 1);
    sig[i] = static_cast<uint8_t>(2 * i + 1);
  }
  const uint32_t w = 1u << p.lg_w;
  bool ok = true;
  for (uint32_t d = 0; d < w; ++d) {
    auto expected = sig;
    std::array<uint8_t, 32> addr{};
    addr[27] = 7;  // chain 7, layer/tree/keypair zero
    for (uint32_t step = d; step + 1 < w; ++step) {
      addr[31] = static_cast<uint8_t>(step);
      const uint8_t* parts[] = {seed.data(), addr.data(), expected.data()};
      const size_t sizes[] = {seed.size(), addr.size(), expected.size()};
      slh_shake256(parts, sizes, 3, expected.data(), expected.size());
    }
    const auto got = slh.wots_endpoint(slh.c.constant(seed), 0, zero, zero, 7,
                                       slh.c.number(d, p.lg_w), slh.c.constant(sig));
    ok &= got == slh.c.constant(expected);
  }
  record(std::string(p.name) + ": all WOTS endpoints match native SHAKE256", ok);
}

// ----------------------------------------------------------------- native

void test_native_vectors(const char* file, const slh_params& p) {
  const Json j = testvec::load_json(vec_path(file));
  const std::string set = j["parameter_set"].str;
  record(set + ": vector file matches the parameters",
         set == p.name && j["h"].num == p.h && j["d"].num == p.d && j["hp"].num == p.hp &&
             j["a"].num == p.a && j["k"].num == p.k && j["lg_w"].num == p.lg_w &&
             j["m"].num == p.m && j["signature_bytes"].num == (long long)slh_sig_bytes(&p));
  std::unique_ptr<slh_key, decltype(&slh_key_free)> key(nullptr, slh_key_free);
  Bytes key_seed;
  size_t n = 0;
  for (const Json& v : j["vectors"].arr) {
    const Bytes sk_seed = unhex(v["sk_seed"].str), sk_prf = unhex(v["sk_prf"].str),
                pk_seed = unhex(v["pk_seed"].str), pk_root = unhex(v["pk_root"].str);
    if (!key || key_seed != sk_seed) {
      const auto t0 = Clock::now();
      key.reset(slh_keygen_internal(&p, sk_seed.data(), sk_prf.data(), pk_seed.data()));
      std::printf("  %s keygen %.2f s on %zu threads\n", set.c_str(), since(t0), slh_threads());
      key_seed = sk_seed;
      uint8_t root[16];
      slh_key_pk_root(key.get(), root);
      record(set + ": PK.root matches", Bytes(root, root + 16) == pk_root);
    }
    const Bytes msg = unhex(v["msg"].str);
    const bool hedged = !v["addrnd"].is_null();
    const Bytes addrnd = hedged ? unhex(v["addrnd"].str) : Bytes();
    Bytes sig(slh_sig_bytes(&p));
    const auto t0 = Clock::now();
    slh_sign(key.get(), msg.data(), msg.size(), hedged ? addrnd.data() : nullptr, sig.data());
    const double sign_s = since(t0);
    const std::string tag = set + " vector " + std::to_string(n++) +
                            (hedged ? " (hedged)" : " (deterministic)");
    char took[32];
    std::snprintf(took, sizeof(took), ", %.2f s", sign_s);
    record(tag + ": signature matches byte for byte" + took, sig == unhex(v["signature"].str));
    Bytes mp(msg.size() + 2);
    slh_pure_message(msg.data(), msg.size(), mp.data());
    slh_stats st{};
    const bool ok = slh_verify_internal(&p, pk_seed.data(), pk_root.data(), mp.data(),
                                        mp.size(), sig.data(), sig.size(), &st);
    record(tag + ": verifies, hash calls match",
           ok && (long long)(st.f + st.h + st.t + 1) == v["verify_hash_calls"].num);
    Bytes digest(p.m);
    slh_h_msg(&p, sig.data(), pk_seed.data(), pk_root.data(), mp.data(), mp.size(),
              digest.data());
    record(tag + ": H_msg digest matches", digest == unhex(v["digest"].str));
    bool rejects = true;
    for (size_t at : {size_t(0), size_t(SLH_N), sig.size() - 1}) {
      Bytes bad = sig;
      bad[at] ^= 1;
      rejects &= !slh_verify(&p, pk_seed.data(), pk_root.data(), msg.data(), msg.size(),
                             bad.data(), bad.size());
    }
    Bytes other = msg;
    other[0] ^= 1;
    rejects &= !slh_verify(&p, pk_seed.data(), pk_root.data(), other.data(), other.size(),
                           sig.data(), sig.size());
    record(tag + ": tampered signature or message rejected", rejects);
  }
}

// ---------------------------------------------------------------- circuit

struct Fixture {
  const slh_params& p;
  SlhSigner signer;
  SlhPublicKey pk;
  SlhUserState state;
  Bytes sig, primary;
  SlhStatement stmt;
};

Fixture make_fixture(const slh_params& p, uint8_t seed, std::span<const uint8_t> doc) {
  uint8_t seeds[48];
  for (size_t i = 0; i < 48; ++i) seeds[i] = uint8_t(seed * 31 + i * 7);
  SlhSigner signer(p, seeds, seeds + 16, seeds + 32);
  const SlhPublicKey pk = signer.public_key();
  const SlhUserState state = slh_commit(doc);
  Bytes sig = signer.sign(state.commitment);
  Bytes primary = slh_primary_witness(p, state, pk, sig);
  return {p, std::move(signer), pk, state, sig, primary, slh_statement(pk, state.digest)};
}

void run_native(const slh_params& p, const SlhStatement& s, const Bytes& primary,
                SlhDims* dims = nullptr) {
  const SlhDims want = slh_dims(p);
  NativeContext e(primary, true, want.primary_bytes);
  SlhCircuit<NativeContext> c(e, p);
  c.statement(s);
  if (dims) *dims = {want.primary_bytes, e.cursor, e.constraints, e.permutations};
}

void test_circuit(const slh_params& p, uint8_t seed) {
  const std::string set = p.name;
  const Bytes doc{'a', 'n', ' ', 'S', 'L', 'H', ' ', 'd', 'o', 'c'};
  const Fixture fx = make_fixture(p, seed, doc);
  SlhDims got{};
  bool ok = true;
  try {
    run_native(p, fx.stmt, fx.primary, &got);
  } catch (const std::exception&) {
    ok = false;
  }
  const SlhDims want = slh_dims(p);
  record(set + ": honest witness satisfies the circuit", ok);
  record(set + ": " + std::to_string(got.permutations) + " permutations, " +
             std::to_string(got.witness_bits / 8) + " witness bytes, " +
             std::to_string(got.constraints) + " constraints, as slh_dims predicts",
         got.witness_bits == want.witness_bits && got.constraints == want.constraints &&
             got.permutations == want.permutations);

  // Authenticated evaluation follows the same witness and constraint order.
  {
    using QS = quicksilver_state<secpar::s128, false, kProofDegree>;
    NativeContext e(fx.primary, true, want.primary_bytes);
    SlhCircuit<NativeContext>(e, p).statement(fx.stmt);
    Bytes extended = e.witness;
    extended.resize(extended.size() + kProofDegree * 16);
    std::vector<block128> macs(extended.size() * 8, block128::set_zero());
    uint8_t challenge[56]{};
    QS qs(extended.data(), macs.data(), e.constraints, challenge);
    AuthContext<false> auth(qs, want.primary_bytes);
    SlhCircuit<AuthContext<false>>(auth, p).statement(fx.stmt);
    record(set + ": authenticated evaluation has the same shape",
           auth.cursor == e.cursor && auth.constraints == e.constraints);
  }

  const size_t sig0 = kSlhSigOffset, fors0 = sig0 + SLH_N;
  const size_t ht0 = sig0 + SLH_N * (1 + p.k * (1 + p.a));
  const size_t len = slh_len(&p);
  const size_t wots_last = ht0 + (p.d - 1) * SLH_N * (len + p.hp) + SLH_N * (len - 1);
  const size_t xmss_auth = ht0 + SLH_N * len + SLH_N * (p.hp - 1) + 7;
  struct Tamper {
    const char* what;
    size_t at;
  } tampers[] = {{"r", 0},
                 {"a", kSlhAOffset + 5},
                 {"R", sig0 + 3},
                 {"a FORS secret", fors0},
                 {"a FORS authentication node", fors0 + SLH_N * p.a + 15},
                 {"the last WOTS+ value", wots_last},
                 {"an XMSS authentication node", xmss_auth}};
  for (const auto& t : tampers) {
    Bytes bad = fx.primary;
    bad[t.at] ^= 1;
    record(set + ": changing " + t.what + " is rejected",
           throws_invalid([&] { run_native(p, fx.stmt, bad); }));
  }
  {
    std::array<uint8_t, 256> other_com = fx.state.commitment;
    other_com[0] ^= 1;
    const Bytes other_sig = fx.signer.sign(other_com);
    Bytes bad = fx.primary;
    std::copy(other_sig.begin(), other_sig.end(), bad.begin() + kSlhSigOffset);
    record(set + ": a signature on another commitment is rejected",
           throws_invalid([&] { run_native(p, fx.stmt, bad); }));
  }
  SlhStatement s = fx.stmt;
  s.pk_root[0] ^= 1;
  record(set + ": another root is rejected",
         throws_invalid([&] { run_native(p, s, fx.primary); }));
  s = fx.stmt;
  s.pk_seed[0] ^= 1;
  record(set + ": another PK.seed is rejected",
         throws_invalid([&] { run_native(p, s, fx.primary); }));
  s = fx.stmt;
  s.message = slh_message_digest(Bytes{'o', 't', 'h', 'e', 'r'});
  record(set + ": another document is rejected",
         throws_invalid([&] { run_native(p, s, fx.primary); }));
}

// --------------------------------------------------------------- protocol

void test_protocol(const slh_params& p) {
  const std::string set = p.name;
  const Bytes doc{'m', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'};
  auto t0 = Clock::now();
  const Fixture fx = make_fixture(p, 9, doc);
  std::printf("  %s keygen + commit + sign %.1f s\n", set.c_str(), since(t0));
  t0 = Clock::now();
  const Bytes proof = slh_unblind(p, fx.state, fx.pk, fx.sig);
  std::printf("  %s prove %.2f s, %zu bytes\n", set.c_str(), since(t0), proof.size());
  t0 = Clock::now();
  record(set + ": the blind signature verifies", slh_verify_signature(p, fx.pk, doc, proof));
  std::printf("  %s verify %.2f s\n", set.c_str(), since(t0));
  const Bytes fresh = slh_unblind(p, fx.state, fx.pk, fx.sig);
  record(set + ": a fresh proof differs and verifies",
         fresh != proof && slh_verify_signature(p, fx.pk, doc, fresh));
  Bytes other = doc;
  other[0] ^= 1;
  record(set + ": another document is rejected", !slh_verify_signature(p, fx.pk, other, proof));
  SlhPublicKey bad = fx.pk;
  bad.pk_root[0] ^= 1;
  record(set + ": another PK.root is rejected", !slh_verify_signature(p, bad, doc, proof));
  bad = fx.pk;
  bad.pk_seed[0] ^= 1;
  record(set + ": another PK.seed is rejected", !slh_verify_signature(p, bad, doc, proof));
  const auto l = slh_proof_layout(p);
  bool altered_ok = true;
  for (size_t at : {size_t(0), size_t(8), l.nonce, l.commitment, l.vole_check, l.correction,
                    l.correction + 4000, l.quicksilver, l.opening, l.delta, l.size - 1}) {
    Bytes alt = proof;
    alt[at] ^= 1;
    altered_ok &= !slh_verify_signature(p, fx.pk, doc, alt);
  }
  record(set + ": every altered proof section is rejected", altered_ok);
  Bytes cut(proof.begin(), proof.end() - 1), longer = proof;
  longer.push_back(0);
  record(set + ": truncated or extended proof is rejected",
         !slh_verify_signature(p, fx.pk, doc, cut) &&
             !slh_verify_signature(p, fx.pk, doc, longer) &&
             !slh_verify_signature(p, fx.pk, doc, Bytes{}));
  record(set + ": the XMSS verifier does not accept it", [&] {
    try {
      return !verify({fx.stmt.message, fx.pk.pk_seed, fx.pk.pk_root, 10}, proof);
    } catch (const std::exception&) {
      return true;
    }
  }());
  Bytes bad_sig = fx.sig;
  bad_sig[SLH_N] ^= 1;
  record(set + ": the user refuses an invalid signer response",
         throws_invalid([&] { slh_primary_witness(p, fx.state, fx.pk, bad_sig); }));
  Bytes bad_primary = fx.primary;
  bad_primary[kSlhSigOffset + SLH_N] ^= 1;
  record(set + ": a tampered witness yields no proof",
         throws_invalid([&] { prove_slh(p, fx.stmt, bad_primary); }));
}
}  // namespace

int main(int argc, char** argv) try {
  const bool quick = argc > 1 && std::string(argv[1]) == "--quick";
  std::printf("== SHAKE256 and the commitment tags ==\n");
  test_sponge_and_tags();
  test_wots_endpoints(kSlhToyW4);
  test_wots_endpoints(kSlhToyW16);
  if (!quick) {
    std::printf("\n== native SLH-DSA-SHAKE against the shared vectors ==\n");
    test_native_vectors("shake-128-24.json", SLH_SHAKE_128_24);
  }
  std::printf("\n== circuit, native and authenticated engines ==\n");
  test_circuit(kSlhToyW4, 41);
  test_circuit(kSlhToyW16, 43);
  if (!quick) test_circuit(kSlhShake128_24, 47);
  std::printf("\n== end-to-end VOLEitH proofs ==\n");
  test_protocol(kSlhToyW4);
  if (!quick) test_protocol(kSlhShake128_24);
  std::printf("\nSLH-DSA test suite %s: %d passed, %d failed\n", failed ? "FAIL" : "PASS",
              passed, failed);
  return failed ? 1 : 0;
} catch (const std::exception& e) {
  std::cerr << "uncaught: " << e.what() << '\n';
  return 1;
}
