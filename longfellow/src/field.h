#ifndef BLIND_LONGFELLOW_FIELD_H_
#define BLIND_LONGFELLOW_FIELD_H_

#include <cstddef>

#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"

namespace blind_longfellow {

using Field = proofs::GF2_128<>;
using Elt = Field::Elt;

using RSFactory = proofs::LCH14ReedSolomonFactory<Field>;

using CompilerBackend = proofs::CompilerBackend<Field>;
using LogicCircuit = proofs::Logic<Field, CompilerBackend>;

constexpr size_t kPluckerSize = 3;

constexpr size_t kLigeroRate = 7;
constexpr size_t kLigeroNreq = 140;

constexpr size_t kTranscriptVersion = 12;
constexpr char kDomainTag[] = "blind-xmss-longfellow-v5-node184-nonce184-seed144";

constexpr size_t kFsNonceBytes = 32;

}

#endif
