/* Longfellow proofs of the SLH-DSA blind-signature statement of
 * circuit/slh_stmt.h. The XMSS prover of prover.h is untouched. */

#ifndef BLIND_LONGFELLOW_SLH_PROVER_H_
#define BLIND_LONGFELLOW_SLH_PROVER_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/sha/flatsha256_witness.h"
#include "sumcheck/circuit.h"

#include "commitment.h"
#include "field.h"
#include "slh/native.h"
#include "slh/params.h"

namespace blind_longfellow {
namespace slh {

using NativeBlock = proofs::FlatSHA256Witness::BlockWitness;

struct SlhPublic {
  Hash mhat;
  Node pk_seed, pk_root;
};

// The native counterpart of SlhWires.
struct SlhWitness {
  SlhPublic pub;
  std::array<FeBytes, kNNonce> r;
  std::array<std::array<FeBytes, kNNonce>, kNLines> a;
  std::array<FeBytes, kNLines> b;
  ByteVec sig;                   // the FIPS 205 encoding
  std::vector<NativeBlock> bw;   // in the order the statement hashes
  bool reaches_root = false;     // the traced verification ends at PK.root
};

// Retraces the statement natively and records every block witness. A wrong
// signature still yields a witness; reaches_root then says it fails.
std::unique_ptr<SlhWitness> build_witness(const SlhParams& p,
                                          const SlhPublic& pub,
                                          const HmCommitment& com,
                                          const CommitmentOpening& opening,
                                          const ByteVec& sig);

std::unique_ptr<proofs::Circuit<Field>> build_slh_circuit(const Field& F,
                                                          const SlhParams& p,
                                                          const Elt pow_x[]);

// Loads `path` if it holds this parameter set's circuit, else compiles and
// saves it.
std::unique_ptr<proofs::Circuit<Field>> build_or_load_slh_circuit(
    const Field& F, const SlhParams& p, const Elt pow_x[],
    const std::string& path, bool* cache_hit = nullptr);

// The cache file of a parameter set inside `dir`.
std::string slh_circuit_cache_path(const SlhParams& p, const std::string& dir);

size_t slh_public_input_count();
size_t slh_input_count(const SlhParams& p);

std::unique_ptr<proofs::Dense<Field>> slh_public_inputs(
    const Field& F, const proofs::Circuit<Field>& circuit, const SlhPublic& pub);

// The proof bytes, or empty if the witness does not satisfy the circuit.
std::vector<uint8_t> slh_prove(const Field& F, const SlhParams& p,
                               const proofs::Circuit<Field>& circuit,
                               const SlhWitness& w);

bool slh_verify_proof(const Field& F, const SlhParams& p,
                      const proofs::Circuit<Field>& circuit,
                      const SlhPublic& pub, const std::vector<uint8_t>& proof);

// Ligero's layout for this circuit, as ZkProof chooses it.
struct LigeroLayout {
  size_t witnesses, block, block_enc, dblock, nrow, nreq, rateinv;
};
LigeroLayout slh_ligero_layout(const proofs::Circuit<Field>& circuit);

}  // namespace slh
}  // namespace blind_longfellow

#endif
