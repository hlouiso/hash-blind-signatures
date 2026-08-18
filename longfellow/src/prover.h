#ifndef BLIND_LONGFELLOW_PROVER_H_
#define BLIND_LONGFELLOW_PROVER_H_

#include <cstddef>
#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "sumcheck/circuit.h"

#include "field.h"
#include "native_witness.h"

namespace blind_longfellow {

std::unique_ptr<proofs::Circuit<Field>> build_circuit(
    const Field& F, const Elt pow_x[kBits128]);

std::unique_ptr<proofs::Dense<Field>> make_public_inputs(
    const Field& F, const proofs::Circuit<Field>& circuit,
    const NativeWitness& nw);

std::vector<uint8_t> blind_prove(const Field& F,
                                  const proofs::Circuit<Field>& circuit,
                                  const NativeWitness& nw);

}

#endif
