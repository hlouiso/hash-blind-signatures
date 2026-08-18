#ifndef BLIND_LONGFELLOW_VERIFIER_H_
#define BLIND_LONGFELLOW_VERIFIER_H_

#include <cstddef>
#include <vector>

#include "arrays/dense.h"
#include "sumcheck/circuit.h"

#include "field.h"

namespace blind_longfellow {

bool blind_verify(const Field& F, const proofs::Circuit<Field>& circuit,
                  const proofs::Dense<Field>& pub,
                  const std::vector<uint8_t>& proof_bytes);

}

#endif
