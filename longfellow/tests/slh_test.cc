/* Tests of the SLH-DSA-SHA2 blind signature: the native code against the
 * shared vectors of ../test-vectors/slh (written by binius64's slh_kat), the
 * circuit on toy parameters with the evaluation backend, and one
 * end-to-end Longfellow proof for SLH-DSA-SHA2-128-24. */

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "util/log.h"
#include "zk/zk_proof.h"

#include "circuit/slh_stmt.h"
#include "field.h"
#include "rng.h"
#include "slh/commit.h"
#include "slh/native.h"
#include "slh/prover.h"
#include "slh/protocol.h"
#include "slh_vectors.h"

namespace blind_longfellow {
namespace slh {
namespace {

using EvalBackend = proofs::EvaluationBackend<Field>;
using EvalLogic = proofs::Logic<Field, EvalBackend>;
using Encoder = proofs::BitPluckerEncoder<Field, kPluckerSize>;
using Clock = std::chrono::steady_clock;
using testvec::Json;
using testvec::unhex;
using testvec::unhex_array;

struct Tally {
  int pass = 0, fail = 0;
  void record(const std::string& name, bool ok) {
    (ok ? pass : fail)++;
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
    std::fflush(stdout);
  }
};

double since(Clock::time_point t) {
  return std::chrono::duration<double>(Clock::now() - t).count();
}

std::string vec_path(const char* file) {
  return std::string(SLH_TEST_VECTOR_DIR) + "/" + file;
}

Bytes str_bytes(const char* s) {
  return Bytes(reinterpret_cast<const uint8_t*>(s),
               reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
}

// ---------------------------------------------------------------- native

void test_native_vectors(Tally& t, const char* file, const SlhParams& p) {
  const Json j = testvec::load_json(vec_path(file));
  const std::string set = j["parameter_set"].str;
  t.record(set + ": vector file matches the parameters",
           set == p.name && j["h"].num == (long long)p.h &&
               j["d"].num == (long long)p.d && j["hp"].num == (long long)p.hp &&
               j["a"].num == (long long)p.a && j["k"].num == (long long)p.k &&
               j["lg_w"].num == (long long)p.lg_w && j["m"].num == (long long)p.m &&
               j["signature_bytes"].num == (long long)p.sig_bytes());
  std::unique_ptr<SlhKey> key;
  size_t n = 0;
  for (const Json& v : j["vectors"].arr) {
    const auto sk_seed = unhex_array<kN>(v["sk_seed"].str);
    const auto sk_prf = unhex_array<kN>(v["sk_prf"].str);
    const auto pk_seed = unhex_array<kN>(v["pk_seed"].str);
    const auto pk_root = unhex_array<kN>(v["pk_root"].str);
    if (!key || key->sk_seed != sk_seed || key->ctx.pk_seed != pk_seed) {
      const auto t0 = Clock::now();
      key = std::make_unique<SlhKey>(
          SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed));
      std::printf("  %s keygen %.2f s on %zu threads\n", set.c_str(), since(t0),
                  signer_threads());
      t.record(set + ": PK.root matches", key->pk_root == pk_root);
      t.record(set + ": PK.seed midstate matches",
               [&] {
                 const State mid = pk_seed_midstate(pk_seed);
                 ByteVec b;
                 for (uint32_t w : mid)
                   for (int s = 24; s >= 0; s -= 8) b.push_back(uint8_t(w >> s));
                 return b == unhex(v["pk_seed_midstate"].str);
               }());
    }
    const ByteVec msg = unhex(v["msg"].str);
    std::optional<Node> addrnd;
    if (!v["addrnd"].is_null()) addrnd = unhex_array<kN>(v["addrnd"].str);
    const auto t0 = Clock::now();
    const SlhSignature sig =
        key->sign(msg.data(), msg.size(), addrnd ? &*addrnd : nullptr);
    const double sign_s = since(t0);
    const ByteVec want = unhex(v["signature"].str);
    const std::string tag =
        set + " vector " + std::to_string(n++) + (addrnd ? " (hedged)" : " (deterministic)");
    t.record(tag + ": signature matches byte for byte, " +
                 std::to_string(sign_s).substr(0, 5) + " s",
             sig.to_bytes() == want);
    const auto parsed = SlhSignature::from_bytes(p, want.data(), want.size());
    t.record(tag + ": decoding round-trips",
             parsed && parsed->to_bytes() == want);
    const ByteVec mp = pure_message(msg.data(), msg.size());
    VerifyStats st;
    const bool ok = key->ctx.verify_internal(pk_root, mp.data(), mp.size(), *parsed, &st);
    t.record(tag + ": verifies, hash calls match",
             ok && (long long)st.hash_calls() == v["verify_hash_calls"].num);
    t.record(tag + ": H_msg digest matches",
             h_msg(parsed->r, pk_seed, pk_root, mp.data(), mp.size(), p.m) ==
                 unhex(v["digest"].str));
    SlhSignature bad = *parsed;
    bad.ht.back().wots.back()[0] ^= 1;
    bool rejects = !slh_verify(p, pk_seed, pk_root, msg.data(), msg.size(), bad);
    bad = *parsed;
    bad.fors[0].auth.back()[15] ^= 0x80;
    rejects &= !slh_verify(p, pk_seed, pk_root, msg.data(), msg.size(), bad);
    ByteVec other = msg;
    other[0] ^= 1;
    rejects &= !slh_verify(p, pk_seed, pk_root, other.data(), other.size(), *parsed);
    t.record(tag + ": tampered signature or message rejected", rejects);
  }
}

void test_commit_vectors(Tally& t, const Field& F) {
  const Json j = testvec::load_json(vec_path("commit-sha256.json"));
  t.record("commitment tags match binius64",
           unhex(j["tag_message"].str) == ByteVec(kTagMessage.begin(), kTagMessage.end()) &&
               unhex(j["tag_nonce"].str) == ByteVec(kTagNonce.begin(), kTagNonce.end()) &&
               unhex(j["tag_digest"].str) == ByteVec(kTagDigest.begin(), kTagDigest.end()));
  size_t n = 0;
  for (const Json& v : j["vectors"].arr) {
    const Bytes msg = unhex(v["msg"].str);
    const ByteVec a_raw = unhex(v["a"].str), r_raw = unhex(v["r"].str);
    std::array<std::array<FeBytes, kNNonce>, kNLines> a;
    std::array<FeBytes, kNNonce> r;
    for (size_t k = 0; k < kNLines; ++k)
      for (size_t i = 0; i < kNNonce; ++i)
        std::memcpy(a[k][i].data(), &a_raw[(k * kNNonce + i) * kFeBytes], kFeBytes);
    for (size_t i = 0; i < kNNonce; ++i)
      std::memcpy(r[i].data(), &r_raw[i * kFeBytes], kFeBytes);
    const HmCommitment com = slh::hm_commit(F, msg, a, r);
    const Hash mh = message_hash(msg);
    ByteVec b;
    for (const auto& bk : com.b) b.insert(b.end(), bk.begin(), bk.end());
    const Hash d = com_digest(com);
    const std::string tag = "commitment vector " + std::to_string(n++);
    t.record(tag + ": m_hat, b, y, encoding and d match",
             ByteVec(mh.begin(), mh.end()) == unhex(v["m_hat"].str) &&
                 b == unhex(v["b"].str) &&
                 ByteVec(com.y.begin(), com.y.end()) == unhex(v["y"].str) &&
                 hm_com_digest_preimage(com) == unhex(v["commitment"].str) &&
                 ByteVec(d.begin(), d.end()) == unhex(v["d"].str));
    t.record(tag + ": opening verifies, a wrong r does not",
             verify_opening(F, com, msg, r) && [&] {
               auto bad = r;
               bad[5][15] ^= 1;
               return !verify_opening(F, com, msg, bad);
             }());
  }
  // Every tag is outside the fixed structure of SLH-DSA-SHA2's other inputs.
  bool apart = kTagMessage != kTagNonce && kTagNonce != kTagDigest &&
               kTagMessage != kTagDigest;
  for (const Tag* tg : {&kTagMessage, &kTagNonce, &kTagDigest}) {
    bool f_h_t_prf = false, ipad = false, opad = false;
    for (size_t i = 16; i < 64; ++i) {
      f_h_t_prf |= (*tg)[i] != 0;
      ipad |= (*tg)[i] != 0x36;
      opad |= (*tg)[i] != 0x5c;
    }
    apart &= f_h_t_prf && ipad && opad && ((*tg)[48] != 0 || (*tg)[49] != 0) &&
             (*tg)[0] != 0x00;  // Longfellow's transcript starts with TAG_BSTR
  }
  t.record("tags are distinct and outside the other SHA-256 domains", apart);
}

// --------------------------------------------------------------- circuit

std::unique_ptr<SlhWires<EvalLogic>> eval_wires(const EvalLogic& L,
                                                const Field& F,
                                                const SlhWitness& w) {
  auto W = std::make_unique<SlhWires<EvalLogic>>();
  auto bytes = [&](std::vector<EvalLogic::v8>& dst, const uint8_t* src, size_t n) {
    dst.clear();
    for (size_t i = 0; i < n; ++i) dst.push_back(L.template vbit<8>(src[i]));
  };
  bytes(W->mhat, w.pub.mhat.data(), kHashBytes);
  bytes(W->pk_seed, w.pub.pk_seed.data(), kN);
  bytes(W->pk_root, w.pub.pk_root.data(), kN);
  const State mid = pk_seed_midstate(w.pub.pk_seed);
  for (size_t i = 0; i < 8; ++i) W->mid[i] = L.template vbit<32>(mid[i]);
  ByteVec r, a, b;
  for (const auto& x : w.r) r.insert(r.end(), x.begin(), x.end());
  for (const auto& line : w.a)
    for (const auto& x : line) a.insert(a.end(), x.begin(), x.end());
  for (const auto& x : w.b) b.insert(b.end(), x.begin(), x.end());
  bytes(W->r, r.data(), r.size());
  bytes(W->a, a.data(), a.size());
  bytes(W->b, b.data(), b.size());
  bytes(W->sig, w.sig.data(), w.sig.size());
  Encoder enc(F);
  auto packed = [&](uint32_t v) {
    const auto e = enc.mkpacked_v32(v);
    StmtFlatSha<EvalLogic>::packed_v32 pv;
    for (size_t j = 0; j < pv.size(); ++j) pv[j] = L.konst(e[j]);
    return pv;
  };
  W->bw.resize(w.bw.size());
  for (size_t i = 0; i < w.bw.size(); ++i) {
    for (size_t k = 0; k < 48; ++k) W->bw[i].outw[k] = packed(w.bw[i].outw[k]);
    for (size_t k = 0; k < 64; ++k) {
      W->bw[i].oute[k] = packed(w.bw[i].oute[k]);
      W->bw[i].outa[k] = packed(w.bw[i].outa[k]);
    }
    for (size_t k = 0; k < 8; ++k) W->bw[i].h1[k] = packed(w.bw[i].h1[k]);
  }
  return W;
}

bool eval_accepts(const Field& F, const SlhParams& p, const SlhWitness& w,
                  const Elt pow_x[]) {
  EvalBackend ebk(F, false);
  EvalLogic L(&ebk, F);
  const auto W = eval_wires(L, F, w);
  assert_slh_statement(L, p, *W, pow_x);
  return !ebk.assertion_failed();
}

struct Fixture {
  SlhParams p;
  std::unique_ptr<SlhKey> key;
  SlhUserState state;
  SlhPublic pub;
  SlhSignature sig;
};

Fixture make_fixture(const Field& F, const SlhParams& p, uint64_t seed,
                     const char* doc) {
  DeterministicRng rng(seed);
  Node sk_seed, sk_prf, pk_seed;
  rng.fill_bytes(sk_seed.data(), kN);
  rng.fill_bytes(sk_prf.data(), kN);
  rng.fill_bytes(pk_seed.data(), kN);
  Fixture fx{p, std::make_unique<SlhKey>(
                    SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed)),
             {}, {}, {}};
  slh_user_commit(F, rng, str_bytes(doc), fx.state);
  fx.sig = slh_signer_sign(*fx.key, fx.state.com, rng);
  fx.pub = {message_hash(fx.state.msg), pk_seed, fx.key->pk_root};
  return fx;
}

void test_circuit(Tally& t, const Field& F, const SlhParams& p,
                  const Elt pow_x[], uint64_t seed) {
  const std::string set = p.name;
  const Fixture fx = make_fixture(F, p, seed, "an SLH-DSA blind signature test document");
  const Hash d = com_digest(fx.state.com);
  t.record(set + ": native signature on d verifies",
           slh_verify(p, fx.pub.pk_seed, fx.pub.pk_root, d.data(), d.size(), fx.sig));
  const ByteVec sig = fx.sig.to_bytes();
  auto witness = [&](const ByteVec& s, const SlhPublic& pub) {
    return build_witness(p, pub, fx.state.com, fx.state.opening, s);
  };
  const auto honest = witness(sig, fx.pub);
  t.record(set + ": " + std::to_string(honest->bw.size()) +
               " SHA-256 blocks, honest witness satisfies the circuit",
           honest->reaches_root && eval_accepts(F, p, *honest, pow_x));

  // Offsets into the FIPS 205 encoding.
  const size_t fors0 = kN, ht0 = kN * (1 + p.k * (1 + p.a));
  const size_t wots_last = ht0 + (p.d - 1) * kN * (p.len() + p.hp) + kN * (p.len() - 1);
  const size_t xmss_auth0 = ht0 + kN * p.len();
  struct Tamper {
    const char* what;
    size_t offset;
    uint8_t mask;
  };
  const Tamper tampers[] = {
      {"R", 3, 0x04},
      {"a FORS secret", fors0, 0x01},
      {"a FORS authentication node", fors0 + kN * p.a + 15, 0x80},
      {"the last WOTS+ value", wots_last, 0x01},
      {"an XMSS authentication node", xmss_auth0 + kN * (p.hp - 1) + 7, 0x02},
  };
  for (const Tamper& tm : tampers) {
    ByteVec bad = sig;
    bad[tm.offset] ^= tm.mask;
    const auto w = witness(bad, fx.pub);
    t.record(set + ": changing " + std::string(tm.what) + " is rejected",
             !w->reaches_root && !eval_accepts(F, p, *w, pow_x));
  }
  {
    const uint8_t zeros[32] = {};
    const ByteVec other = fx.key->sign(zeros, 32, nullptr).to_bytes();
    const auto w = witness(other, fx.pub);
    t.record(set + ": a signature on another commitment is rejected",
             !w->reaches_root && !eval_accepts(F, p, *w, pow_x));
  }
  {
    SlhPublic pub = fx.pub;
    pub.pk_root[0] ^= 1;
    t.record(set + ": another root is rejected",
             !eval_accepts(F, p, *witness(sig, pub), pow_x));
    pub = fx.pub;
    pub.pk_seed[0] ^= 1;
    t.record(set + ": another PK.seed is rejected",
             !eval_accepts(F, p, *witness(sig, pub), pow_x));
    pub = fx.pub;
    pub.mhat = message_hash(str_bytes("another document"));
    t.record(set + ": another document is rejected",
             !eval_accepts(F, p, *witness(sig, pub), pow_x));
  }
  {
    auto w = witness(sig, fx.pub);
    w->bw[w->bw.size() / 2].h1[1] ^= 1;
    t.record(set + ": an inconsistent SHA-256 block witness is rejected",
             !eval_accepts(F, p, *w, pow_x));
    w = witness(sig, fx.pub);
    w->r[0][0] ^= 1;
    t.record(set + ": a wrong commitment opening is rejected",
             !eval_accepts(F, p, *w, pow_x));
  }
}

// -------------------------------------------------------------- protocol

void test_protocol(Tally& t, const Field& F, const SlhParams& p,
                   const Elt pow_x[]) {
  const std::string set = p.name;
  auto t0 = Clock::now();
  bool hit = false;
  const auto circuit = build_or_load_slh_circuit(
      F, p, pow_x, slh_circuit_cache_path(p, SLH_CIRCUIT_CACHE_DIR), &hit);
  std::printf("  %s circuit %s in %.1f s: ninputs=%zu npub_in=%zu nlayers=%zu\n",
              set.c_str(), hit ? "loaded" : "compiled", since(t0),
              circuit->ninputs, circuit->npub_in, circuit->nl);
  t0 = Clock::now();
  const Fixture fx = make_fixture(F, p, 0x5148A, "my secret message");
  std::printf("  %s keygen + commit + sign %.1f s\n", set.c_str(), since(t0));
  const SlhPublicKey pk{fx.pub.pk_seed, fx.pub.pk_root};

  t0 = Clock::now();
  const auto proof = slh_user_prove(F, p, *circuit, fx.state, pk, fx.sig);
  std::printf("  %s prove %.2f s, %zu bytes\n", set.c_str(), since(t0), proof.size());
  t.record(set + ": user_prove produced a proof", !proof.empty());
  t0 = Clock::now();
  t.record(set + ": the blind signature verifies",
           slh_verify_blind(F, p, *circuit, pk, proof, fx.state.msg));
  std::printf("  %s verify %.2f s\n", set.c_str(), since(t0));
  const auto fresh = slh_user_prove(F, p, *circuit, fx.state, pk, fx.sig);
  t.record(set + ": a fresh proof differs and verifies",
           fresh != proof && slh_verify_blind(F, p, *circuit, pk, fresh, fx.state.msg));

  proofs::set_log_level(proofs::ERROR);
  t.record(set + ": another document is rejected",
           !slh_verify_blind(F, p, *circuit, pk, proof, str_bytes("a different message")));
  SlhPublicKey bad = pk;
  bad.pk_root[0] ^= 1;
  t.record(set + ": another PK.root is rejected",
           !slh_verify_blind(F, p, *circuit, bad, proof, fx.state.msg));
  bad = pk;
  bad.pk_seed[0] ^= 1;
  t.record(set + ": another PK.seed is rejected",
           !slh_verify_blind(F, p, *circuit, bad, proof, fx.state.msg));
  for (size_t at : {size_t{0}, proof.size() / 2, proof.size() - 1}) {
    auto altered = proof;
    altered[at] ^= 1;
    t.record(set + ": proof byte " + std::to_string(at) + " flipped is rejected",
             !slh_verify_blind(F, p, *circuit, pk, altered, fx.state.msg));
  }
  auto cut = proof;
  cut.pop_back();
  auto longer = proof;
  longer.push_back(0);
  t.record(set + ": truncated or extended proof is rejected",
           !slh_verify_blind(F, p, *circuit, pk, cut, fx.state.msg) &&
               !slh_verify_blind(F, p, *circuit, pk, longer, fx.state.msg) &&
               !slh_verify_blind(F, p, *circuit, pk, {}, fx.state.msg));
  {
    ByteVec sig = fx.sig.to_bytes();
    sig[kN * (1 + p.k * (1 + p.a))] ^= 1;  // the first WOTS+ value
    const auto w = build_witness(p, fx.pub, fx.state.com, fx.state.opening, sig);
    t.record(set + ": a tampered signature yields no proof",
             slh_prove(F, p, *circuit, *w).empty());
  }
  proofs::set_log_level(proofs::INFO);
}

int run(int argc, char** argv) {
  proofs::set_log_level(proofs::ERROR);
  const Field F;
  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);
  Tally t;
  const bool quick = argc > 1 && std::string(argv[1]) == "--quick";

  if (!quick) {
    std::printf("== native SLH-DSA-SHA2 against the shared vectors ==\n");
    test_native_vectors(t, "sha2-128-24.json", kSlhSha2_128_24);
    std::printf("\n");
  }
  std::printf("== tagged SHA-256 commitment ==\n");
  test_commit_vectors(t, F);
  std::printf("\n== circuit, evaluation backend ==\n");
  test_circuit(t, F, kSlhToyW4, pow_x, 41);
  test_circuit(t, F, kSlhToyW16, pow_x, 43);
  if (!quick) {
    test_circuit(t, F, kSlhSha2_128_24, pow_x, 47);
    std::printf("\n== end-to-end Longfellow proof ==\n");
    test_protocol(t, F, kSlhSha2_128_24, pow_x);
  }
  std::printf("\nSLH-DSA test suite %s: %d passed, %d failed\n",
              t.fail == 0 ? "PASS" : "FAIL", t.pass, t.fail);
  return t.fail == 0 ? 0 : 1;
}

}  // namespace
}  // namespace slh
}  // namespace blind_longfellow

int main(int argc, char** argv) { return blind_longfellow::slh::run(argc, argv); }
