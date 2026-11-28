#include "slh/prover.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

#include <fstream>
#include <limits>
#include <stdexcept>

#include "zstd.h"

#include "circuit/slh_stmt.h"
#include "sha_witness_encoding.h"
#include "slh/commit.h"
#include "slh/wide_circuit_io.h"

namespace blind_longfellow {
namespace slh {
namespace {

using proofs::Dense;
using proofs::DenseFiller;
constexpr size_t kBlockWitnessWords = 48 + 64 + 64 + 8;

// SHA-256 calls of the statement, recorded block by block.
struct Tracer {
  std::vector<NativeBlock> bw;

  ByteVec sha(const State& h0, const ByteVec& msg, size_t prefix,
              size_t out_bytes) {
    const size_t nb = sha_blocks_after(msg.size());
    ByteVec in(64 * nb, 0);
    std::memcpy(in.data(), msg.data(), msg.size());
    in[msg.size()] = 0x80;
    const uint64_t bits = static_cast<uint64_t>(prefix + msg.size()) * 8;
    for (size_t k = 0; k < 8; ++k)
      in[64 * nb - 1 - k] = static_cast<uint8_t>(bits >> (8 * k));
    uint32_t h[8];
    std::memcpy(h, h0.data(), sizeof(h));
    for (size_t b = 0; b < nb; ++b) {
      uint32_t w[16];
      for (size_t i = 0; i < 16; ++i)
        w[i] = proofs::SHA256_ru32be(&in[64 * b + 4 * i]);
      NativeBlock x;
      proofs::FlatSHA256Witness::transform_and_witness_block(w, h, x.outw, x.oute,
                                                            x.outa, x.h1);
      std::memcpy(h, x.h1, sizeof(h));
      bw.push_back(x);
    }
    ByteVec out(out_bytes);
    for (size_t i = 0; i < out_bytes; ++i)
      out[i] = static_cast<uint8_t>(h[i / 4] >> (24 - 8 * (i % 4)));
    return out;
  }

  Node thash(const State& mid, const Adrs& adrs, const ByteVec& data) {
    const auto c = adrs.compressed();
    ByteVec msg(c.begin(), c.end());
    msg.insert(msg.end(), data.begin(), data.end());
    const ByteVec out = sha(mid, msg, 64, kN);
    Node n;
    std::memcpy(n.data(), out.data(), kN);
    return n;
  }
};

ByteVec cat(std::initializer_list<const ByteVec*> parts) {
  ByteVec out;
  for (const ByteVec* p : parts) out.insert(out.end(), p->begin(), p->end());
  return out;
}

ByteVec bytes_of(const Node& n) { return ByteVec(n.begin(), n.end()); }

std::string domain_tag(const SlhParams& p) {
  return std::string("blind-slh-dsa-longfellow-v2/") + p.name;
}

void fill_public(DenseFiller<Field>& fill, const Field& F, const SlhPublic& pub) {
  fill.push_back(F.one());
  push_bytes(fill, F, pub.mhat.data(), pub.mhat.size());
  push_bytes(fill, F, pub.pk_seed.data(), kN);
  push_bytes(fill, F, pub.pk_root.data(), kN);
  const State mid = pk_seed_midstate(pub.pk_seed);
  for (uint32_t word : mid) fill.push_back(static_cast<uint64_t>(word), 32, F);
}

void fill_all(DenseFiller<Field>& fill, const Field& F, const SlhWitness& w) {
  fill_public(fill, F, w.pub);
  for (const auto& r_i : w.r) push_bytes(fill, F, r_i.data(), kFeBytes);
  for (const auto& line : w.a)
    for (const auto& a_i : line) push_bytes(fill, F, a_i.data(), kFeBytes);
  for (const auto& b_k : w.b) push_bytes(fill, F, b_k.data(), kFeBytes);
  push_bytes(fill, F, w.sig.data(), w.sig.size());
  ShaWordEncoder enc(F);
  for (const auto& bw : w.bw) push_block_witness(fill, enc, bw);
}

}  // namespace

std::unique_ptr<SlhWitness> build_witness(const SlhParams& p,
                                          const SlhPublic& pub,
                                          const HmCommitment& com,
                                          const CommitmentOpening& opening,
                                          const ByteVec& sig_bytes) {
  proofs::check(sig_bytes.size() == p.sig_bytes(), "build_witness: signature size");
  auto w = std::make_unique<SlhWitness>();
  w->pub = pub;
  w->r = opening.r;
  w->a = com.a;
  w->b = com.b;
  w->sig = sig_bytes;
  const auto sig = SlhSignature::from_bytes(p, sig_bytes.data(), sig_bytes.size());
  const SlhCtx ctx(p, pub.pk_seed);
  Tracer tr;

  ByteVec r_bytes, com_bytes;
  for (const auto& r_i : opening.r) r_bytes.insert(r_bytes.end(), r_i.begin(), r_i.end());
  const ByteVec y = tr.sha(tag_midstate(kTagNonce), r_bytes, kTagBytes, kHashBytes);
  com_bytes = hm_com_digest_preimage(com);
  std::memcpy(com_bytes.data() + kComBytes - kHashBytes, y.data(), kHashBytes);
  const ByteVec d = tr.sha(tag_midstate(kTagDigest), com_bytes, kTagBytes, kHashBytes);

  // H_msg with M' = 0x00 || 0x00 || d.
  const ByteVec R = bytes_of(sig->r), seed = bytes_of(pub.pk_seed),
                root = bytes_of(pub.pk_root), zero2(2, 0), zero4(4, 0);
  const ByteVec inner = tr.sha(kSha256Iv, cat({&R, &seed, &root, &zero2, &d}), 0, kHashBytes);
  const ByteVec digest = tr.sha(kSha256Iv, cat({&R, &seed, &inner, &zero4}), 0, p.m);
  const DigestParts dp = ctx.split_digest(digest);

  // FORS, Algorithm 17.
  const auto idx = base_2b(dp.md.data(), p.a, p.k);
  const Adrs fors = SlhCtx::fors_adrs(dp.idx_tree, dp.idx_leaf);
  ByteVec roots;
  for (uint32_t i = 0; i < p.k; ++i) {
    const uint32_t leaf_index = (i << p.a) + idx[i];
    Adrs a = fors;
    a.set_tree_height(0);
    a.set_tree_index(leaf_index);
    Node node = tr.thash(ctx.mid, a, bytes_of(sig->fors[i].sk));
    for (uint32_t j = 0; j < p.a; ++j) {
      const Node& sib = sig->fors[i].auth[j];
      a.set_tree_height(j + 1);
      a.set_tree_index(leaf_index >> (j + 1));
      const bool right = (idx[i] >> j) & 1;
      const ByteVec l = bytes_of(right ? sib : node), rr = bytes_of(right ? node : sib);
      node = tr.thash(ctx.mid, a, cat({&l, &rr}));
    }
    roots.insert(roots.end(), node.begin(), node.end());
  }
  Adrs pk = fors;
  pk.set_type_and_clear(kForsRoots);
  pk.set_keypair(dp.idx_leaf);
  Node node = tr.thash(ctx.mid, pk, roots);

  // Algorithm 13 with fixed chain slots.
  uint64_t tree = dp.idx_tree;
  uint32_t leaf = dp.idx_leaf;
  for (uint32_t layer = 0; layer < p.d; ++layer) {
    if (layer > 0) {
      leaf = static_cast<uint32_t>(tree & ((uint64_t{1} << p.hp) - 1));
      tree >>= p.hp;
    }
    Adrs base;
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_type_and_clear(kWotsHash);
    base.set_keypair(leaf);
    const auto digits = ctx.wots_digits(node);
    ByteVec ends;
    for (uint32_t i = 0; i < p.len(); ++i) {
      Node x = sig->ht[layer].wots[i];
      for (uint32_t s = 0; s + 1 < p.w(); ++s) {
        Adrs a = base;
        a.set_chain(i);
        a.set_hash(s);
        const Node y_s = tr.thash(ctx.mid, a, bytes_of(x));
        if (digits[i] <= s) x = y_s;
      }
      ends.insert(ends.end(), x.begin(), x.end());
    }
    Adrs wpk = base;
    wpk.set_type_and_clear(kWotsPk);
    wpk.set_keypair(leaf);
    node = tr.thash(ctx.mid, wpk, ends);
    Adrs t = base;
    t.set_type_and_clear(kTree);
    for (uint32_t k = 0; k < p.hp; ++k) {
      const Node& sib = sig->ht[layer].auth[k];
      t.set_tree_height(k + 1);
      t.set_tree_index(leaf >> (k + 1));
      const bool right = (leaf >> k) & 1;
      const ByteVec l = bytes_of(right ? sib : node), rr = bytes_of(right ? node : sib);
      node = tr.thash(ctx.mid, t, cat({&l, &rr}));
    }
  }
  w->reaches_root = node == pub.pk_root;
  w->bw = std::move(tr.bw);
  proofs::check(w->bw.size() == SlhShape(p).total(), "build_witness: block count");
  return w;
}

size_t slh_public_input_count() { return 1 + 8 * (kHashBytes + 2 * kN) + 32 * 8; }

size_t slh_input_count(const SlhParams& p) {
  const size_t private_bits = 8 * (kRBodyBytes + kNLines * kNNonce * kFeBytes +
                                   kNLines * kFeBytes + p.sig_bytes());
  const size_t per_block =
      kBlockWitnessWords * ShaWordPlucker<LogicCircuit>::kNv32Elts;
  return slh_public_input_count() + private_bits + SlhShape(p).total() * per_block;
}

std::unique_ptr<proofs::Circuit<Field>> build_slh_circuit(const Field& F,
                                                          const SlhParams& p,
                                                          const Elt pow_x[]) {
  proofs::QuadCircuit<Field> Q(F);
  CompilerBackend cbk(&Q);
  LogicCircuit lc(&cbk, F);
  auto W = std::make_unique<SlhWires<LogicCircuit>>();
  auto bytes = [&](std::vector<LogicCircuit::v8>& v, size_t n) {
    v.resize(n);
    for (auto& b : v) b = lc.template vinput<8>();
  };
  bytes(W->mhat, kHashBytes);
  bytes(W->pk_seed, kN);
  bytes(W->pk_root, kN);
  for (auto& word : W->mid) word = lc.template vinput<32>();
  Q.private_input();
  bytes(W->r, kRBodyBytes);
  bytes(W->a, kNLines * kNNonce * kFeBytes);
  bytes(W->b, kNLines * kFeBytes);
  bytes(W->sig, p.sig_bytes());
  W->bw.resize(SlhShape(p).total());
  for (auto& bw : W->bw) bw.input(lc);
  Q.begin_full_field();
  assert_slh_statement(lc, p, *W, pow_x);
  auto circuit = Q.mkcircuit(1);
  proofs::check(circuit->npub_in == slh_public_input_count() &&
                    circuit->ninputs == slh_input_count(p),
                "build_slh_circuit: input layout");
  return circuit;
}

std::string slh_circuit_cache_path(const SlhParams& p, const std::string& dir) {
  // Bump the suffix whenever circuit/slh_stmt.h changes the circuit.
  return dir + "/" + p.name + "-v2.cache";
}

namespace {

constexpr char kCacheMagic[4] = {'B', 'L', 'S', 'W'};
constexpr int kCacheZstdLevel = 3;

void save_wide_circuit(const Field& F, const proofs::Circuit<Field>& circuit,
                       const std::string& path) {
  std::vector<uint8_t> raw;
  WideCircuitWriter<Field>(F, proofs::GF2_128_ID).to_bytes(circuit, raw);
  std::vector<uint8_t> comp(ZSTD_compressBound(raw.size()));
  const size_t n =
      ZSTD_compress(comp.data(), comp.size(), raw.data(), raw.size(), kCacheZstdLevel);
  if (ZSTD_isError(n))
    throw std::runtime_error(std::string("ZSTD_compress: ") + ZSTD_getErrorName(n));
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("cannot write " + path);
  f.write(kCacheMagic, sizeof(kCacheMagic));
  f.write(reinterpret_cast<const char*>(comp.data()), static_cast<std::streamsize>(n));
  if (!f) throw std::runtime_error("write failed: " + path);
}

// WideCircuitReader requests at most one term or circuit ID at a time. Keep
// those reads contiguous even when a term straddles a decompression boundary.
class CacheInput {
 public:
  struct InvalidFrame {};
  CacheInput(const uint8_t* data, size_t size, size_t raw_size)
      : input_{data, size, 0}, remaining_(raw_size),
        ctx_(ZSTD_createDCtx(), ZSTD_freeDCtx), buffer_(ZSTD_DStreamOutSize()) {
    if (!ctx_) throw std::bad_alloc();
  }
  bool have(size_t n) const { return n <= remaining_; }

  const uint8_t* next(size_t n) {
    if (!have(n) || n > buffer_.size()) throw InvalidFrame{};
    if (end_ - pos_ < n) {
      const size_t left = end_ - pos_;
      std::memmove(buffer_.data(), buffer_.data() + pos_, left);
      pos_ = 0;
      end_ = left;
      while (end_ < n) refill();
    }
    const uint8_t* result = buffer_.data() + pos_;
    pos_ += n;
    remaining_ -= n;
    return result;
  }
  void next(size_t n, uint8_t* dest) { std::memcpy(dest, next(n), n); }

  bool complete() {
    if (remaining_ || pos_ != end_) return false;
    pos_ = end_ = 0;
    while (!ended_ && !end_) refill();
    return ended_ && !end_ && input_.pos == input_.size;
  }

 private:
  void refill() {
    if (ended_) throw InvalidFrame{};
    const size_t start = input_.pos;
    ZSTD_outBuffer out{buffer_.data(), buffer_.size(), end_};
    const size_t ret = ZSTD_decompressStream(ctx_.get(), &out, &input_);
    if (ZSTD_isError(ret) || (ret && start == input_.pos && end_ == out.pos))
      throw InvalidFrame{};
    ended_ = ret == 0;
    end_ = out.pos;
  }
  ZSTD_inBuffer input_;
  size_t remaining_, pos_ = 0, end_ = 0;
  bool ended_ = false;
  std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> ctx_;
  std::vector<uint8_t> buffer_;
};

std::unique_ptr<proofs::Circuit<Field>> load_wide_circuit(const Field& F,
                                                          const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  const std::streamoff size = f.tellg();
  if (size <= static_cast<std::streamoff>(sizeof(kCacheMagic))) return nullptr;
  f.seekg(0);
  char magic[sizeof(kCacheMagic)];
  if (!f.read(magic, sizeof(magic)) || std::memcmp(magic, kCacheMagic, sizeof(magic)))
    return nullptr;
  std::vector<uint8_t> comp(static_cast<size_t>(size) - sizeof(magic));
  if (!f.read(reinterpret_cast<char*>(comp.data()), comp.size())) return nullptr;
  const auto raw_len = ZSTD_getFrameContentSize(comp.data(), comp.size());
  if (raw_len == ZSTD_CONTENTSIZE_ERROR || raw_len == ZSTD_CONTENTSIZE_UNKNOWN ||
      raw_len > std::numeric_limits<size_t>::max())
    return nullptr;
  try {
    CacheInput input(comp.data(), comp.size(), static_cast<size_t>(raw_len));
    WideCircuitReader<Field, CacheInput> reader(F, proofs::GF2_128_ID);
    auto circuit = reader.from_bytes(input, true);
    return circuit && input.complete() ? std::move(circuit) : nullptr;
  } catch (const CacheInput::InvalidFrame&) {
    return nullptr;
  }
}

}  // namespace

std::unique_ptr<proofs::Circuit<Field>> build_or_load_slh_circuit(
    const Field& F, const SlhParams& p, const Elt pow_x[],
    const std::string& path, bool* cache_hit) {
  if (auto cached = load_wide_circuit(F, path)) {
    if (cached->npub_in == slh_public_input_count() &&
        cached->ninputs == slh_input_count(p)) {
      if (cache_hit) *cache_hit = true;
      return cached;
    }
  }
  if (cache_hit) *cache_hit = false;
  auto circuit = build_slh_circuit(F, p, pow_x);
  save_wide_circuit(F, *circuit, path);
  return circuit;
}

std::unique_ptr<Dense<Field>> slh_public_inputs(
    const Field& F, const proofs::Circuit<Field>& circuit, const SlhPublic& pub) {
  auto in = std::make_unique<Dense<Field>>(1, circuit.npub_in);
  DenseFiller<Field> fill(*in);
  fill_public(fill, F, pub);
  proofs::check(fill.size() == circuit.npub_in, "slh_public_inputs: size");
  return in;
}

std::vector<uint8_t> slh_prove(const Field& F, const SlhParams& p,
                               const proofs::Circuit<Field>& circuit,
                               const SlhWitness& w) {
  auto W = std::make_unique<Dense<Field>>(1, circuit.ninputs);
  {
    DenseFiller<Field> fill(*W);
    fill_all(fill, F, w);
    proofs::check(fill.size() == circuit.ninputs, "slh_prove: witness size");
  }
  const RSFactory rsf(F);
  proofs::ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);
  proofs::SecureRandomEngine rng;
  const std::string tag = domain_tag(p);
  proofs::Transcript tp(reinterpret_cast<const uint8_t*>(tag.data()), tag.size(),
                        kTranscriptVersion);
  proofs::ZkProver<Field, RSFactory> prover(circuit, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  if (!prover.prove(zkpr, *W, tp)) return {};
  std::vector<uint8_t> buf;
  zkpr.write(buf, F);
  return buf;
}

bool slh_verify_proof(const Field& F, const SlhParams& p,
                      const proofs::Circuit<Field>& circuit,
                      const SlhPublic& pub, const std::vector<uint8_t>& proof) {
  if (proof.empty()) return false;
  const auto in = slh_public_inputs(F, circuit, pub);
  const RSFactory rsf(F);
  proofs::ZkProof<Field> zkpv(circuit, kLigeroRate, kLigeroNreq);
  proofs::ReadBuffer rb(proof.data(), proof.size());
  if (!zkpv.read(rb, F) || rb.remaining() != 0) return false;
  proofs::ZkVerifier<Field, RSFactory> verifier(circuit, rsf, kLigeroRate,
                                                kLigeroNreq, F);
  const std::string tag = domain_tag(p);
  proofs::Transcript tv(reinterpret_cast<const uint8_t*>(tag.data()), tag.size(),
                        kTranscriptVersion);
  verifier.recv_commitment(zkpv, tv);
  return verifier.verify(zkpv, *in, tv);
}

LigeroLayout slh_ligero_layout(const proofs::Circuit<Field>& circuit) {
  const proofs::ZkProof<Field> z(circuit, kLigeroRate, kLigeroNreq);
  return {z.param.nw,    z.param.block, z.param.block_enc, z.param.dblock,
          z.param.nrow,  z.param.nreq,  z.param.rateinv};
}

}  // namespace slh
}  // namespace blind_longfellow
