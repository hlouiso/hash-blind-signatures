#pragma once
// VOLE-in-the-head proofs of the SLH-DSA-SHAKE statement of slh_circuit.hpp,
// with the FAEST/QuickSilver pipeline and the parameters of proof.cpp
// (tau, degree, grinding). The XMSS proof of proof.hpp is untouched.
#include "proof.hpp"
#include "slh_circuit.hpp"

namespace voleith {

// Wire version: fixes the SLH circuit, field, degree, tau and domains.
inline constexpr std::array<uint8_t, 8> kSlhProofVersion{'H', 'B', 'V', 'S',
                                                         'L', 'H', '0', '1'};

// Parameter sets with a compiled proof system: SLH-DSA-SHAKE-128-24 and the
// one-layer toy set.
bool slh_proof_supported(const slh_params& p);
SlhDims slh_proof_dims(const slh_params& p);
ProofLayout slh_proof_layout(const slh_params& p);
Bytes prove_slh(const slh_params& p, const SlhStatement& s, const Bytes& primary);
bool verify_slh(const slh_params& p, const SlhStatement& s,
                std::span<const uint8_t> proof);

}  // namespace voleith
