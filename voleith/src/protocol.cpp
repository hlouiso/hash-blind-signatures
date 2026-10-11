#include "protocol.hpp"
extern "C" {
#include "native/randombytes.h"
}

namespace voleith {
namespace {
void random(std::span<uint8_t> out) {
  if (!randombytes_fill(out.data(), out.size()))
    throw std::runtime_error("OS random source failed");
}

void validate_key(const SecretKey& key) {
  if (key.height < 1 || key.height > 32 ||
      key.next_leaf > (uint64_t(1) << key.height))
    throw std::invalid_argument("invalid XMSS secret key state");
}

Statement statement(const PublicKey& pk,
                    const std::array<uint8_t, 32>& digest) {
  return {digest, pk.seed, pk.root};
}

Bytes frame(char kind, size_t n) {
  Bytes b(8 + n);
  const char magic[] = "HBVO001";
  memcpy(b.data(), magic, 7);
  b[7] = kind;
  return b;
}

const uint8_t* payload(std::span<const uint8_t> b, char kind, size_t n) {
  const auto prefix = frame(kind, 0);
  if (b.size() != 8 + n || !std::equal(prefix.begin(), prefix.end(), b.begin()))
    throw std::invalid_argument("wrong artifact type, version or length");
  return b.data() + 8;
}

uint64_t load64(const uint8_t* p) {
  uint64_t v = 0;
  for (size_t i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
  return v;
}

void store64(uint8_t* p, uint64_t v) {
  for (size_t i = 0; i < 8; ++i) p[i] = v >> (8 * i);
}
}

Signer::Signer(SecretKey key) : key_(key), tree_(nullptr, xmss_keypair_free) {
  validate_key(key_);
  tree_.reset(
      xmss_keypair_new(key_.seed.data(), key_.public_seed.data(), key_.height));
  if (!tree_) throw std::runtime_error("XMSS tree generation failed");
}

Signer Signer::generate(int height) {
  if (height < 1 || height > 32)
    throw std::invalid_argument("XMSS height must be in [1,32]");
  SecretKey k{};
  k.height = height;
  random(k.seed);
  random(k.public_seed);
  return Signer(k);
}

PublicKey Signer::public_key() const {
  PublicKey pk{key_.public_seed, {}};
  xmss_keypair_root(tree_.get(), pk.root.data());
  return pk;
}

xmss_sig Signer::sign(const Commitment& com,
                      const std::function<void(const SecretKey&)>& persist) {
  if (key_.next_leaf == (uint64_t(1) << key_.height))
    throw std::runtime_error("XMSS key exhausted");
  const auto leaf = static_cast<uint32_t>(key_.next_leaf++);
  if (persist) persist(key_);
  std::array<uint8_t, 32> d;
  hm_digest(com.data(), d.data());
  xmss_sig sig{};
  if (!xmss_keypair_sign(tree_.get(), leaf, d.data(), d.size(), &sig))
    throw std::runtime_error("XMSS signing failed; reserved leaf consumed");
  return sig;
}

std::array<uint8_t, 32> message_digest(std::span<const uint8_t> message) {
  std::array<uint8_t, 32> digest;
  const uint8_t domain[] = {'M', 'S', 'G'};
  shake_th(domain, sizeof(domain), message.data(), message.size(),
           digest.data(), digest.size());
  return digest;
}

UserState commit(std::span<const uint8_t> message) {
  UserState s{};
  s.digest = message_digest(message);
  random(s.r);
  std::array<uint8_t, 192> a;
  random(a);
  std::array<uint8_t, 32> d;
  hm_commit(s.digest.data(), s.r.data(), a.data(), s.commitment.data(),
            d.data());
  return s;
}

Bytes primary_witness(const UserState& state, const PublicKey& pk,
                      const xmss_sig& sig) {
  std::array<uint8_t, 256> com;
  std::array<uint8_t, 32> d;
  hm_commit(state.digest.data(), state.r.data(), state.commitment.data(),
            com.data(), d.data());
  if (com != state.commitment)
    throw std::invalid_argument("inconsistent HM opening");
  if (!xmss_verify(pk.seed.data(), pk.root.data(), d.data(), d.size(), &sig))
    throw std::invalid_argument("invalid XMSS signer response");
  Bytes p(kPrimaryBytes);
  memcpy(p.data(), state.r.data(), 96);
  memcpy(p.data() + 96, state.commitment.data(), 192);
  xmss_write_sig(&sig, p.data() + kSigOffset);
  uint8_t digest[32], coords[42];
  xmss_hash_message(pk.seed.data(), sig.leaf_index, sig.nonce, 24, d.data(), 32,
                    digest);
  if (!xmss_extract_coords(digest, coords))
    throw std::invalid_argument("invalid target-sum codeword");
  size_t at = kScheduleOffset;
  for (size_t i = 0; i < 42; ++i)
    for (size_t j = coords[i]; j < 7; ++j) p.at(at++) = i;
  if (at != kEndpointsOffset) throw std::logic_error("chain schedule length");
  xmss_wots_pk_from_sig(
      pk.seed.data(), sig.leaf_index, sig.sig_hashes, coords,
      reinterpret_cast<xmss_node*>(p.data() + kEndpointsOffset));
  return p;
}

Bytes unblind(const UserState& s, const PublicKey& pk,
              const xmss_sig& response) {
  return prove(statement(pk, s.digest), primary_witness(s, pk, response));
}

bool verify_signature(const PublicKey& pk, std::span<const uint8_t> message,
                      std::span<const uint8_t> signature) {
  return verify(statement(pk, message_digest(message)), signature);
}

Bytes encode(const PublicKey& pk) {
  auto b = frame('P', 32);
  memcpy(b.data() + 8, pk.seed.data(), 16);
  memcpy(b.data() + 24, pk.root.data(), 16);
  return b;
}

PublicKey decode_public(std::span<const uint8_t> b) {
  auto p = payload(b, 'P', 32);
  PublicKey pk;
  memcpy(pk.seed.data(), p, 16);
  memcpy(pk.root.data(), p + 16, 16);
  return pk;
}

Bytes encode(const SecretKey& sk) {
  validate_key(sk);
  auto b = frame('K', 57);
  auto p = b.data() + 8;
  memcpy(p, sk.seed.data(), 32);
  memcpy(p + 32, sk.public_seed.data(), 16);
  p[48] = sk.height;
  store64(p + 49, sk.next_leaf);
  return b;
}

SecretKey decode_secret(std::span<const uint8_t> b) {
  auto p = payload(b, 'K', 57);
  SecretKey sk;
  memcpy(sk.seed.data(), p, 32);
  memcpy(sk.public_seed.data(), p + 32, 16);
  sk.height = p[48];
  sk.next_leaf = load64(p + 49);
  validate_key(sk);
  return sk;
}

Bytes encode(const UserState& s) {
  auto b = frame('U', 384);
  auto p = b.data() + 8;
  memcpy(p, s.digest.data(), 32);
  memcpy(p + 32, s.r.data(), 96);
  memcpy(p + 128, s.commitment.data(), 256);
  return b;
}

UserState decode_state(std::span<const uint8_t> b) {
  auto p = payload(b, 'U', 384);
  UserState s;
  memcpy(s.digest.data(), p, 32);
  memcpy(s.r.data(), p + 32, 96);
  memcpy(s.commitment.data(), p + 128, 256);
  return s;
}

Bytes encode(const Commitment& com) {
  auto b = frame('C', 256);
  memcpy(b.data() + 8, com.data(), 256);
  return b;
}

Commitment decode_commitment(std::span<const uint8_t> b) {
  auto p = payload(b, 'C', 256);
  Commitment c;
  memcpy(c.data(), p, 256);
  return c;
}

Bytes encode(const xmss_sig& sig) {
  auto b = frame('S', XMSS_SIG_BYTES);
  xmss_write_sig(&sig, b.data() + 8);
  return b;
}

xmss_sig decode_response(std::span<const uint8_t> b) {
  auto p = payload(b, 'S', XMSS_SIG_BYTES);
  xmss_sig s{};
  if (!xmss_read_sig(p, XMSS_SIG_BYTES, &s))
    throw std::invalid_argument("invalid XMSS encoding");
  return s;
}
}
