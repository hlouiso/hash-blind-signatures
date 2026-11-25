#include "slh/protocol.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

#include "../protocol.h"
#include "slh/commit.h"

namespace blind_longfellow {
namespace slh {

HmCommitment slh_user_commit(const Field& F, Rng& rng, const Bytes& msg,
                             SlhUserState& state) {
  auto [com, opening] = slh::sample_commitment(F, rng, msg);
  state = SlhUserState{msg, com, opening};
  return com;
}

SlhSignature slh_signer_sign(const SlhKey& key, const HmCommitment& com,
                             Rng& rng) {
  const Hash d = com_digest(com);
  Node addrnd;
  rng.fill_bytes(addrnd.data(), addrnd.size());
  return key.sign(d.data(), d.size(), &addrnd);
}

std::vector<uint8_t> slh_user_prove(const Field& F, const SlhParams& p,
                                    const proofs::Circuit<Field>& circuit,
                                    const SlhUserState& state,
                                    const SlhPublicKey& pk,
                                    const SlhSignature& sig) {
  const SlhPublic pub{message_hash(state.msg), pk.pk_seed, pk.pk_root};
  const ByteVec bytes = sig.to_bytes();
  if (bytes.size() != p.sig_bytes()) return {};
  const auto w = build_witness(p, pub, state.com, state.opening, bytes);
  if (!w->reaches_root) return {};
  return slh_prove(F, p, circuit, *w);
}

bool slh_verify_blind(const Field& F, const SlhParams& p,
                      const proofs::Circuit<Field>& circuit,
                      const SlhPublicKey& pk, const std::vector<uint8_t>& proof,
                      const Bytes& msg) {
  return slh_verify_proof(F, p, circuit, {message_hash(msg), pk.pk_seed, pk.pk_root},
                          proof);
}

const Magic kSlhKeyMagic = {'H', 'B', 'S', '-', 'S', 'L', 'H', 'K'};
const Magic kSlhPubMagic = {'H', 'B', 'S', '-', 'S', 'L', 'H', 'P'};
const Magic kSlhSigMagic = {'H', 'B', 'S', '-', 'S', 'L', 'H', 'S'};
const Magic kSlhStateMagic = {'H', 'B', 'S', '-', 'S', 'L', 'H', 'U'};

namespace {

// Parameter sets a file can name. Only SHA2-128-24 has a compiled circuit.
constexpr uint8_t kSet128_24 = 1;

uint8_t set_id(const SlhParams& p) {
  if (std::string(p.name) == kSlhSha2_128_24.name) return kSet128_24;
  throw std::runtime_error(std::string("no file identifier for ") + p.name);
}

[[noreturn]] void malformed(const char* what) {
  throw std::runtime_error(std::string("malformed ") + what);
}

std::vector<uint8_t> header(const Magic& magic, const SlhParams& p) {
  std::vector<uint8_t> out(magic.begin(), magic.end());
  out.push_back(set_id(p));
  return out;
}

// The body after magic and set byte, which must be `body` bytes long.
const uint8_t* body(const std::vector<uint8_t>& buf, const Magic& magic,
                    size_t body, SlhParams* p, const char* what) {
  if (!has_magic(buf, magic) || buf.size() != magic.size() + 1 + body ||
      buf[magic.size()] != kSet128_24)
    malformed(what);
  if (p) *p = kSlhSha2_128_24;
  return buf.data() + magic.size() + 1;
}

void push(std::vector<uint8_t>& out, const Node& n) {
  out.insert(out.end(), n.begin(), n.end());
}

Node node_at(const uint8_t* q, size_t i) {
  Node n;
  std::memcpy(n.data(), q + i * kN, kN);
  return n;
}

}  // namespace

bool has_magic(const std::vector<uint8_t>& buf, const Magic& magic) {
  return buf.size() >= magic.size() &&
         std::equal(magic.begin(), magic.end(), buf.begin());
}

std::vector<uint8_t> write_slh_key(const SlhParams& p, const SlhSecretKey& key) {
  auto out = header(kSlhKeyMagic, p);
  for (const Node* n : {&key.sk_seed, &key.sk_prf, &key.pk_seed, &key.pk_root})
    push(out, *n);
  return out;
}

SlhSecretKey read_slh_key(const std::vector<uint8_t>& buf, SlhParams* p) {
  const uint8_t* q = body(buf, kSlhKeyMagic, 4 * kN, p, "SLH-DSA signer key");
  return {node_at(q, 0), node_at(q, 1), node_at(q, 2), node_at(q, 3)};
}

std::vector<uint8_t> write_slh_pub(const SlhParams& p, const SlhPublicKey& pk) {
  auto out = header(kSlhPubMagic, p);
  push(out, pk.pk_seed);
  push(out, pk.pk_root);
  return out;
}

SlhPublicKey read_slh_pub(const std::vector<uint8_t>& buf, SlhParams* p) {
  const uint8_t* q = body(buf, kSlhPubMagic, 2 * kN, p, "SLH-DSA public key");
  return {node_at(q, 0), node_at(q, 1)};
}

std::vector<uint8_t> write_slh_sig(const SlhParams& p, const SlhSignature& sig) {
  auto out = header(kSlhSigMagic, p);
  const ByteVec bytes = sig.to_bytes();
  if (bytes.size() != p.sig_bytes()) malformed("SLH-DSA signature");
  out.insert(out.end(), bytes.begin(), bytes.end());
  return out;
}

SlhSignature read_slh_sig(const std::vector<uint8_t>& buf, const SlhParams& p) {
  const uint8_t* q = body(buf, kSlhSigMagic, p.sig_bytes(), nullptr, "SLH-DSA signature");
  auto sig = SlhSignature::from_bytes(p, q, p.sig_bytes());
  if (!sig) malformed("SLH-DSA signature");
  return *sig;
}

std::vector<uint8_t> write_slh_user_state(const SlhUserState& state) {
  std::vector<uint8_t> out(kSlhStateMagic.begin(), kSlhStateMagic.end());
  const auto rest = write_user_state(UserState{state.msg, state.com, state.opening});
  out.insert(out.end(), rest.begin(), rest.end());
  return out;
}

SlhUserState read_slh_user_state(const std::vector<uint8_t>& buf) {
  if (!has_magic(buf, kSlhStateMagic)) malformed("SLH-DSA user state");
  const std::vector<uint8_t> rest(buf.begin() + kSlhStateMagic.size(), buf.end());
  const UserState s = read_user_state(rest);
  return {s.msg, s.com, s.opening};
}

}  // namespace slh
}  // namespace blind_longfellow
