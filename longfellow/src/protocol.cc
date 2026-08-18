#include "protocol.h"

#include <cstring>

#include "util/panic.h"

#include "sha.h"
#include "wots.h"

namespace blind_longfellow {
namespace {

static void push_u32le(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>(v));
  out.push_back(static_cast<uint8_t>(v >> 8));
  out.push_back(static_cast<uint8_t>(v >> 16));
  out.push_back(static_cast<uint8_t>(v >> 24));
}

class NonceAttemptRng final : public Rng {
 public:
  NonceAttemptRng(const uint8_t sk_seed[kSkSeedBytes], const PkSeed& pk_seed,
                  uint32_t leaf, const Hash& commitment_digest) {
    static constexpr uint8_t kNoncePrfLabel[] =
        "blind-xmss-longfellow/nonce/v1";
    key_ = hmac_sha256(sk_seed, kSkSeedBytes, kNoncePrfLabel,
                       sizeof(kNoncePrfLabel) - 1);

    context_.reserve(kPkSeedBytes + 4 + kHashBytes);
    context_.insert(context_.end(), pk_seed.begin(), pk_seed.end());
    push_u32le(context_, leaf);
    context_.insert(context_.end(), commitment_digest.begin(),
                    commitment_digest.end());
  }

  void fill_bytes(uint8_t* out, size_t n) override {
    proofs::check(n == kNonceLength,
                  "NonceAttemptRng requires one full nonce");
    Bytes input = context_;
    push_u32le(input, attempt_++);
    const Hash block = hmac_sha256(key_, input);
    std::memcpy(out, block.data(), n);
  }

 private:
  Hash key_{};
  Bytes context_;
  uint32_t attempt_ = 0;
};

static uint32_t read_u32le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0])
       | (static_cast<uint32_t>(p[1]) << 8)
       | (static_cast<uint32_t>(p[2]) << 16)
       | (static_cast<uint32_t>(p[3]) << 24);
}

static void push_bytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
  out.insert(out.end(), p, p + n);
}

static void push_hash(std::vector<uint8_t>& out, const Hash& h) {
  push_bytes(out, h.data(), kHashBytes);
}

static Hash read_hash(const uint8_t* p) {
  Hash h;
  std::memcpy(h.data(), p, kHashBytes);
  return h;
}

static void push_node(std::vector<uint8_t>& out, const Node& n) {
  push_bytes(out, n.data(), kNodeBytes);
}

static Node read_node(const uint8_t* p) {
  Node n;
  std::memcpy(n.data(), p, kNodeBytes);
  return n;
}

static void push_pk_seed(std::vector<uint8_t>& out, const PkSeed& seed) {
  push_bytes(out, seed.data(), kPkSeedBytes);
}

static PkSeed read_pk_seed(const uint8_t* p) {
  PkSeed seed;
  std::memcpy(seed.data(), p, kPkSeedBytes);
  return seed;
}

static void push_commitment(std::vector<uint8_t>& out, const HmCommitment& com) {
  for (const auto& line : com.a)
    for (const auto& a_i : line) push_bytes(out, a_i.data(), kFeBytes);
  for (const auto& b_k : com.b) push_bytes(out, b_k.data(), kFeBytes);
  push_hash(out, com.y);
}

static HmCommitment parse_commitment(const uint8_t* p) {
  HmCommitment com;
  for (size_t k = 0; k < kNLines; ++k)
    for (size_t i = 0; i < kNNonce; ++i) {
      std::memcpy(com.a[k][i].data(), p, kFeBytes);
      p += kFeBytes;
    }
  for (size_t k = 0; k < kNLines; ++k) {
    std::memcpy(com.b[k].data(), p, kFeBytes);
    p += kFeBytes;
  }
  com.y = read_hash(p);
  return com;
}

}

HmCommitment user_commit(const Field& F, Rng& rng, const Bytes& msg,
                          UserState& out_state) {
  auto [com, opening] = sample_commitment(F, rng, msg);
  out_state = UserState{msg, com, opening};
  return com;
}

std::optional<XmssSignature> signer_sign(SignerKey& key,
                                          const HmCommitment& com) {

  const Hash d = hm_com_digest(com);
  XmssKeyPair kp =
      XmssKeyPair::generate_from_seed(key.sk_seed, key.pk_seed, key.height);
  kp.set_next_leaf(key.next_leaf);

  const WinternitzSpec spec = xmss_wots_spec();
  NonceAttemptRng rng(key.sk_seed, key.pk_seed, key.next_leaf, d);

  auto sig = kp.sign(spec, rng, d.data(), d.size());
  if (sig.has_value()) key.next_leaf = kp.next_leaf();
  return sig;
}

BlindSignature user_prove(const Field& F,
                           const proofs::Circuit<Field>& circuit,
                           const UserState& state,
                           const XmssSignature& xmss_sig) {
  auto nw = NativeWitness::build_from(F, state.msg, state.com,
                                      state.opening, xmss_sig);
  const auto proof = blind_prove(F, circuit, *nw);
  return BlindSignature{proof};
}

bool verify_blind_sig(const Field& F, const proofs::Circuit<Field>& circuit,
                      const Node& xmss_root, const PkSeed& pk_seed,
                      const BlindSignature& sig, const Bytes& msg) {

  auto nw = std::make_unique<NativeWitness>();
  const Hash m_hat = sha256(msg);
  std::memcpy(nw->m_hat, m_hat.data(), kHashBytes);
  const Bytes dp = build_wots_domain_param(pk_seed);
  std::memcpy(nw->domain_param, dp.data(), kDomainParamLen);
  nw->xmss_root = xmss_root;

  auto pub = make_public_inputs(F, circuit, *nw);
  return blind_verify(F, circuit, *pub, sig.proof);
}

std::vector<uint8_t> write_signer_key(const SignerKey& key) {
  std::vector<uint8_t> out;
  out.reserve(kSkSeedBytes + kPkSeedBytes + 1 + 8);
  push_bytes(out, key.sk_seed, kSkSeedBytes);
  push_pk_seed(out, key.pk_seed);
  out.push_back(key.height);
  for (int k = 0; k < 8; ++k) {
    out.push_back(static_cast<uint8_t>((key.next_leaf >> (8 * k)) & 0xff));
  }
  return out;
}

SignerKey read_signer_key(const std::vector<uint8_t>& buf) {
  proofs::check(buf.size() == kSkSeedBytes + kPkSeedBytes + 1 + 8,
                "read_signer_key: wrong size");
  SignerKey key;
  std::memcpy(key.sk_seed, buf.data(), kSkSeedBytes);
  key.pk_seed = read_pk_seed(buf.data() + kSkSeedBytes);
  size_t o = kSkSeedBytes + kPkSeedBytes;
  key.height = buf[o++];
  proofs::check(key.height >= 1 && key.height <= kXmssH,
                "read_signer_key: height out of range");
  key.next_leaf = 0;
  for (int k = 0; k < 8; ++k) {
    key.next_leaf |= static_cast<uint64_t>(buf[o++]) << (8 * k);
  }
  return key;
}

std::vector<uint8_t> write_signer_pub(const Node& xmss_root, const PkSeed& pk_seed) {
  std::vector<uint8_t> out;
  out.reserve(kNodeBytes + kPkSeedBytes);
  push_node(out, xmss_root);
  push_pk_seed(out, pk_seed);
  return out;
}

std::pair<Node, PkSeed> read_signer_pub(const std::vector<uint8_t>& buf) {
  proofs::check(buf.size() == kNodeBytes + kPkSeedBytes,
                "read_signer_pub: wrong size");
  return {read_node(buf.data()), read_pk_seed(buf.data() + kNodeBytes)};
}

std::vector<uint8_t> write_commitment(const HmCommitment& com) {
  std::vector<uint8_t> out;
  out.reserve(kComBytes);
  push_commitment(out, com);
  return out;
}

HmCommitment read_commitment(const std::vector<uint8_t>& buf) {
  proofs::check(buf.size() == kComBytes, "read_commitment: expected 256 bytes");
  return parse_commitment(buf.data());
}

std::vector<uint8_t> write_user_state(const UserState& state) {
  std::vector<uint8_t> out;
  out.reserve(4 + state.msg.size() + kComBytes + kNNonce * kFeBytes);
  push_u32le(out, static_cast<uint32_t>(state.msg.size()));
  push_bytes(out, state.msg.data(), state.msg.size());
  push_commitment(out, state.com);
  for (const auto& r_i : state.opening.r)
    push_bytes(out, r_i.data(), kFeBytes);
  return out;
}

UserState read_user_state(const std::vector<uint8_t>& buf) {
  proofs::check(buf.size() >= 4, "read_user_state: too short");
  const uint32_t msg_len = read_u32le(buf.data());
  proofs::check(buf.size() == 4 + msg_len + kComBytes + kNNonce * kFeBytes,
                "read_user_state: wrong size");
  const uint8_t* p = buf.data() + 4;
  UserState state;
  state.msg.assign(p, p + msg_len); p += msg_len;
  state.com = parse_commitment(p); p += kComBytes;
  for (size_t i = 0; i < kNNonce; ++i) {
    std::memcpy(state.opening.r[i].data(), p, kFeBytes);
    p += kFeBytes;
  }
  state.opening.msg = state.msg;
  return state;
}

constexpr size_t kXmssSigBytes =
    4 + kNonceLength + kLen * kNodeBytes + kXmssH * kNodeBytes;

std::vector<uint8_t> write_xmss_sig(const XmssSignature& sig) {
  proofs::check(sig.wots.sig_hashes.size() == kLen, "write_xmss_sig: sig_hashes");
  proofs::check(sig.wots.nonce.size() == kNonceLength, "write_xmss_sig: nonce");

  std::vector<uint8_t> out;
  out.reserve(kXmssSigBytes);

  push_u32le(out, sig.leaf_index);
  push_bytes(out, sig.wots.nonce.data(), kNonceLength);
  for (const auto& h : sig.wots.sig_hashes) push_node(out, h);
  for (const auto& h : sig.auth_path) push_node(out, h);

  proofs::check(out.size() == kXmssSigBytes, "write_xmss_sig: size mismatch");
  return out;
}

std::optional<XmssSignature> read_xmss_sig(const std::vector<uint8_t>& buf,
                                           const PkSeed& pk_seed,
                                           const uint8_t* message,
                                           size_t message_len) {
  if (buf.size() != kXmssSigBytes) return std::nullopt;
  const uint8_t* p = buf.data();

  const uint32_t leaf_index = read_u32le(p); p += 4;
  Bytes nonce(p, p + kNonceLength); p += kNonceLength;
  std::vector<Node> sig_hashes(kLen);
  for (auto& h : sig_hashes) { h = read_node(p); p += kNodeBytes; }
  AuthPath auth_path;
  for (size_t h = 0; h < kXmssH; ++h) { auth_path[h] = read_node(p); p += kNodeBytes; }

  return xmss_expand(xmss_wots_spec(), pk_seed, leaf_index, nonce, sig_hashes,
                     auth_path, message, message_len);
}

std::vector<uint8_t> write_blind_sig(const BlindSignature& sig) {
  return sig.proof;
}

BlindSignature read_blind_sig(const std::vector<uint8_t>& buf) {
  return BlindSignature{buf};
}

}
