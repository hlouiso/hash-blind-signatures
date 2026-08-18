#include "prover.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"

#include "circuit/blind_stmt.h"
#include "commitment.h"
#include "field.h"
#include "native_witness.h"
#include "sha.h"
#include "wots.h"
#include "xmss.h"

namespace blind_longfellow {
namespace {

using proofs::Circuit;
using proofs::Dense;
using proofs::DenseFiller;
using proofs::QuadCircuit;
using proofs::SecureRandomEngine;
using proofs::Transcript;
using proofs::ZkProof;
using proofs::ZkProver;

using Encoder = proofs::BitPluckerEncoder<Field, kPluckerSize>;

static void push_bytes(DenseFiller<Field>& fill, const Field& F,
                       const uint8_t* b, size_t n) {
  for (size_t i = 0; i < n; ++i)
    fill.push_back(static_cast<uint64_t>(b[i]), 8, F);
}

static void push_digest(DenseFiller<Field>& fill, const Field& F,
                        const uint8_t d[kHashBytes]) {
  for (size_t j = 0; j < 256; ++j) {
    const int bit = (d[(255 - j) / 8] >> (j % 8)) & 1;
    fill.push_back(bit ? F.one() : F.zero());
  }
}

static void push_node(DenseFiller<Field>& fill, const Field& F,
                      const uint8_t d[kNodeBytes]) {
  for (size_t i = 0; i < kNodeBits; ++i) {
    const int bit = (d[kNodeBytes - 1 - i / 8] >> (i % 8)) & 1;
    fill.push_back(bit ? F.one() : F.zero());
  }
}

static void push_block_witness(DenseFiller<Field>& fill, Encoder& enc,
                               const NativeBW& bw) {
  for (size_t k = 0; k < 48; ++k) fill.push_back(enc.mkpacked_v32(bw.outw[k]));
  for (size_t k = 0; k < 64; ++k) {
    fill.push_back(enc.mkpacked_v32(bw.oute[k]));
    fill.push_back(enc.mkpacked_v32(bw.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) fill.push_back(enc.mkpacked_v32(bw.h1[k]));
}

static void fill_public(DenseFiller<Field>& fill, const Field& F,
                        const NativeWitness& nw) {
  fill.push_back(F.one());
  push_bytes(fill, F, nw.m_hat, kHashBytes);
  push_bytes(fill, F, nw.domain_param, kDomainParamLen);
  push_node(fill, F, nw.xmss_root.data());

  const Midstate mid = tree_midstate(
      Bytes(nw.domain_param, nw.domain_param + kDomainParamLen));
  for (size_t k = 0; k < 8; ++k)
    fill.push_back(static_cast<uint64_t>(mid[k]), 32, F);
}

static void fill_all(DenseFiller<Field>& fill, const Field& F,
                     const NativeWitness& nw) {
  fill_public(fill, F, nw);
  Encoder enc(F);

  for (size_t i = 0; i < kNNonce; ++i)
    push_bytes(fill, F, nw.r_bytes[i].data(), kFeBytes);
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i)
      push_bytes(fill, F, nw.a_bytes[k][i].data(), kFeBytes);
  for (size_t k = 0; k < kNLines; ++k)
    push_bytes(fill, F, nw.b_bytes[k].data(), kFeBytes);
  for (size_t j = 0; j < kRevealBlocks; ++j)
    push_block_witness(fill, enc, nw.reveal_bw[j]);
  for (size_t j = 0; j < kComBlocks; ++j)
    push_block_witness(fill, enc, nw.com_bw[j]);

  push_bytes(fill, F, nw.nonce, kNonceLength);
  for (size_t j = 0; j < kMsgBlocks; ++j)
    push_block_witness(fill, enc, nw.msg_bw[j]);

  for (size_t i = 0; i < kLen; ++i) {
    push_node(fill, F, nw.sig_hashes[i].data());
    push_node(fill, F, nw.pk_hashes[i].data());
  }
  for (size_t j = 0; j < kPooledChainLen; ++j) {
    push_node(fill, F, nw.step_in[j].data());
    fill.push_back(static_cast<uint64_t>(nw.step_chain_idx[j]), 8, F);
    fill.push_back(static_cast<uint64_t>(nw.step_count[j]), 8, F);
    fill.push_back(static_cast<uint64_t>(nw.step_position[j]), 8, F);
    for (size_t b = 0; b < kChainBlocks; ++b)
      push_block_witness(fill, enc, nw.step_bw[j][b]);
  }

  for (size_t j = 0; j < kLtreeBlocks; ++j)
    push_block_witness(fill, enc, nw.leaf_bw[j]);

  fill.push_back(static_cast<uint64_t>(nw.leaf_index), 32, F);
  for (size_t h = 0; h < kXmssH; ++h) {
    push_node(fill, F, nw.auth_path[h].data());
    for (size_t b = 0; b < kTreeBlocks; ++b)
      push_block_witness(fill, enc, nw.merkle_bw[h][b]);
  }

}

}

std::unique_ptr<proofs::Circuit<Field>> build_circuit(
    const Field& F, const Elt pow_x[kBits128]) {
  QuadCircuit<Field> Q(F);
  CompilerBackend cbk(&Q);
  LogicCircuit lc(&cbk, F);

  auto W_ptr = std::make_unique<StatementWires<LogicCircuit>>();
  StatementWires<LogicCircuit>& W = *W_ptr;

  for (size_t j = 0; j < kHashBytes; ++j)
    W.commit.mhat[j] = lc.template vinput<8>();
  for (size_t j = 0; j < kDomainParamLen; ++j)
    W.shared.domain_param[j] = lc.template vinput<8>();
  W.xmss.xmss_root = lc.template vinput<kNodeBits>();
  for (size_t k = 0; k < 8; ++k)
    W.shared.merkle_midstate[k] = lc.template vinput<32>();

  Q.private_input();

  for (size_t i = 0; i < kNNonce; ++i)
    for (size_t j = 0; j < kFeBytes; ++j)
      W.commit.r_bytes[i][j] = lc.template vinput<8>();
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i)
      for (size_t j = 0; j < kFeBytes; ++j)
        W.commit.a_bytes[k][i][j] = lc.template vinput<8>();
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t j = 0; j < kFeBytes; ++j)
      W.commit.b_bytes[k][j] = lc.template vinput<8>();
  for (size_t j = 0; j < kRevealBlocks; ++j) W.commit.reveal_bw[j].input(lc);
  for (size_t j = 0; j < kComBlocks; ++j) W.commit.com_bw[j].input(lc);

  for (size_t j = 0; j < kNonceLength; ++j)
    W.xmss.nonce[j] = lc.template vinput<8>();
  for (size_t j = 0; j < kMsgBlocks; ++j) W.xmss.msg_bw[j].input(lc);

  for (size_t i = 0; i < kLen; ++i) {
    W.xmss.sig_hash[i] = lc.template vinput<kNodeBits>();
    W.xmss.pk_hash[i]  = lc.template vinput<kNodeBits>();
  }
  for (size_t j = 0; j < kPooledChainLen; ++j) {
    W.xmss.step_in[j]  = lc.template vinput<kNodeBits>();
    W.xmss.step_chain_idx[j] = lc.template vinput<8>();
    W.xmss.step_count[j]     = lc.template vinput<8>();
    W.xmss.step_position[j]  = lc.template vinput<8>();
    for (size_t b = 0; b < kChainBlocks; ++b) W.xmss.step_bw[j][b].input(lc);
  }

  for (size_t j = 0; j < kLtreeBlocks; ++j) W.xmss.leaf_bw[j].input(lc);

  W.leaf_index = lc.template vinput<32>();
  for (size_t h = 0; h < kXmssH; ++h) {
    W.xmss.auth[h]   = lc.template vinput<kNodeBits>();
    for (size_t b = 0; b < kTreeBlocks; ++b) W.xmss.merkle_bw[h][b].input(lc);
  }

  Q.begin_full_field();

  assert_statement(lc, F, W, pow_x);
  return Q.mkcircuit(1);
}

std::unique_ptr<proofs::Dense<Field>> make_public_inputs(
    const Field& F, const proofs::Circuit<Field>& circuit,
    const NativeWitness& nw) {
  auto pub = std::make_unique<Dense<Field>>(1, circuit.ninputs);
  DenseFiller<Field> fill(*pub);
  fill_public(fill, F, nw);
  proofs::check(fill.size() == circuit.npub_in, "make_public_inputs: size mismatch");
  return pub;
}

std::vector<uint8_t> blind_prove(const Field& F,
                                  const proofs::Circuit<Field>& circuit,
                                  const NativeWitness& nw) {
  auto W = std::make_unique<Dense<Field>>(1, circuit.ninputs);
  {
    DenseFiller<Field> fill(*W);
    fill_all(fill, F, nw);
    proofs::check(fill.size() == circuit.ninputs, "blind_prove: witness size mismatch");
  }

  const RSFactory rsf(F);
  ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);
  SecureRandomEngine rng;
  std::array<uint8_t, kFsNonceBytes> fs_nonce{};
  rng.bytes(fs_nonce.data(), fs_nonce.size());
  Transcript tp(reinterpret_cast<const uint8_t*>(kDomainTag),
                sizeof(kDomainTag) - 1, kTranscriptVersion);
  tp.write(fs_nonce.data(), fs_nonce.size());
  ZkProver<Field, RSFactory> prover(circuit, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  if (!prover.prove(zkpr, *W, tp)) return {};

  std::vector<uint8_t> buf(fs_nonce.begin(), fs_nonce.end());
  zkpr.write(buf, F);
  return buf;
}

}
