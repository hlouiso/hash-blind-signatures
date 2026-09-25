#include "verifier.h"

#include <cstddef>
#include <vector>

#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"

#include "field.h"

namespace blind_longfellow {

bool blind_verify(const Field& F, const proofs::Circuit<Field>& circuit,
                  const proofs::Dense<Field>& pub,
                  const std::vector<uint8_t>& proof_bytes) {
  if (proof_bytes.empty()) return false;

  const RSFactory rsf(F);
  proofs::ZkProof<Field> zkpv(circuit, kLigeroRate, kLigeroNreq);
  proofs::ReadBuffer rb(proof_bytes.data(), proof_bytes.size());
  if (!zkpv.read(rb, F) || rb.remaining() != 0) return false;

  proofs::ZkVerifier<Field, RSFactory> verifier(circuit, rsf, kLigeroRate,
                                                kLigeroNreq, F);
  proofs::Transcript tv(reinterpret_cast<const uint8_t*>(kDomainTag),
                        sizeof(kDomainTag) - 1, kTranscriptVersion);
  verifier.recv_commitment(zkpv, tv);
  return verifier.verify(zkpv, pub, tv);
}

}
