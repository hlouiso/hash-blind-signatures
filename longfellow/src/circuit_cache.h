#ifndef BLIND_LONGFELLOW_CIRCUIT_CACHE_H_
#define BLIND_LONGFELLOW_CIRCUIT_CACHE_H_

#include <memory>
#include <string>

#include "sumcheck/circuit.h"

#include "field.h"
#include "prover.h"

namespace blind_longfellow {

const char* default_circuit_cache_path();

void save_circuit(const Field& F, const proofs::Circuit<Field>& circuit,
                  const std::string& path);

std::unique_ptr<proofs::Circuit<Field>> load_circuit(const Field& F,
                                                     const std::string& path);

std::unique_ptr<proofs::Circuit<Field>> build_or_load_circuit(
    const Field& F, const Elt pow_x[kBits128], const std::string& path,
    bool* cache_hit = nullptr);

}

#endif
