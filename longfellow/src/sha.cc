#include "sha.h"

#include <cstring>
#include <limits>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "circuits/sha/flatsha256_witness.h"
#include "util/crypto.h"
#include "util/panic.h"

namespace blind_longfellow {

namespace {

void push_le(Bytes& out, uint64_t v, size_t width) {
  for (size_t k = 0; k < width; ++k) out.push_back((v >> (8 * k)) & 0xff);
}
}

Hash sha256(const uint8_t* data, size_t n) {
  proofs::SHA256 h;
  h.Update(data, n);
  Hash out;
  h.DigestData(out.data());
  return out;
}

Hash hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data,
                 size_t data_len) {
  proofs::check(key_len <= static_cast<size_t>(std::numeric_limits<int>::max()),
                "HMAC-SHA-256 key too long");
  Hash out;
  unsigned int out_len = 0;
  const unsigned char* result =
      HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, data_len,
           out.data(), &out_len);
  proofs::check(result == out.data() && out_len == out.size(),
                "HMAC-SHA-256 failed");
  return out;
}

Node sha256_node(const uint8_t* data, size_t n) {
  const Hash full = sha256(data, n);
  Node out;
  std::memcpy(out.data(), full.data(), kNodeBytes);
  return out;
}

Bytes build_wots_domain_param(const PkSeed& pk_seed) {
  return Bytes(pk_seed.begin(), pk_seed.end());
}

Bytes build_message_hash(const Bytes& param, uint32_t epoch,
                         const uint8_t* nonce, size_t nonce_len,
                         const uint8_t* message, size_t message_len) {
  Bytes m;
  m.reserve(param.size() + 1 + kEpochBytes + nonce_len + message_len);
  m.insert(m.end(), param.begin(), param.end());
  m.push_back(kMessageTweak);
  push_le(m, epoch, kEpochBytes);
  m.insert(m.end(), nonce, nonce + nonce_len);
  m.insert(m.end(), message, message + message_len);
  return m;
}

Bytes build_chain_hash(const Bytes& param, uint32_t epoch, const Node& hash,
                       uint64_t chain_idx, uint64_t position) {

  Bytes m;
  m.reserve(param.size() + 1 + kEpochBytes + kNodeBytes + 1 + 1);
  m.insert(m.end(), param.begin(), param.end());
  m.push_back(kChainTweak);
  push_le(m, epoch, kEpochBytes);
  m.insert(m.end(), hash.begin(), hash.end());
  push_le(m, chain_idx, 1);
  push_le(m, position, 1);
  return m;
}

Bytes build_tree_prefix(const Bytes& param) {
  proofs::check(param.size() + 1 <= kTreePrefixBytes, "tree prefix overflows a block");
  Bytes m(kTreePrefixBytes, 0);
  std::memcpy(m.data(), param.data(), param.size());
  m[param.size()] = kNodeTweak;
  return m;
}

Midstate tree_midstate(const Bytes& param) {

  static const uint32_t kIV[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                  0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                  0x1f83d9abu, 0x5be0cd19u};
  const Bytes prefix = build_tree_prefix(param);
  uint32_t in[16];
  for (size_t i = 0; i < 16; ++i)
    in[i] = proofs::SHA256_ru32be(prefix.data() + 4 * i);

  uint32_t outw[48], oute[64], outa[64];
  Midstate h1{};
  proofs::FlatSHA256Witness::transform_and_witness_block(in, kIV, outw, oute,
                                                         outa, h1.data());
  return h1;
}

Bytes build_tree_hash(const Bytes& param, const Node& left, const Node& right,
                      uint32_t level, uint32_t index) {

  Bytes m = build_tree_prefix(param);
  m.reserve(kTreePrefixBytes + 1 + 4 + kNodeBytes + kNodeBytes);
  push_le(m, level, 1);
  push_le(m, index, 4);
  m.insert(m.end(), left.begin(), left.end());
  m.insert(m.end(), right.begin(), right.end());
  return m;
}

Bytes build_public_key_hash(const Bytes& param, uint32_t epoch,
                            const std::vector<Node>& pk_hashes) {
  Bytes m;
  m.reserve(param.size() + 1 + kEpochBytes + pk_hashes.size() * kNodeBytes);
  m.insert(m.end(), param.begin(), param.end());
  m.push_back(kTreeTweak);
  push_le(m, epoch, kEpochBytes);
  for (const Node& pk : pk_hashes) m.insert(m.end(), pk.begin(), pk.end());
  return m;
}

Hash hash_message(const Bytes& param, uint32_t epoch, const uint8_t* nonce,
                  size_t nonce_len, const uint8_t* message, size_t message_len) {
  return sha256(build_message_hash(param, epoch, nonce, nonce_len, message,
                                   message_len));
}

Node hash_chain(const Bytes& param, uint32_t epoch, const Node& hash,
                uint64_t chain_idx, uint64_t position) {

  uint8_t buf[64];
  const size_t plen = param.size();
  proofs::check(plen + 1 + kEpochBytes + kNodeBytes + 1 + 1 <= sizeof(buf),
                "param too long");
  size_t o = 0;
  std::memcpy(buf + o, param.data(), plen);
  o += plen;
  buf[o++] = kChainTweak;
  for (size_t k = 0; k < kEpochBytes; ++k)
    buf[o++] = static_cast<uint8_t>((epoch >> (8 * k)) & 0xff);
  std::memcpy(buf + o, hash.data(), kNodeBytes);
  o += kNodeBytes;
  buf[o++] = static_cast<uint8_t>(chain_idx & 0xff);
  buf[o++] = static_cast<uint8_t>(position & 0xff);
  return sha256_node(buf, o);
}

Node hash_chain_multi(const Bytes& param, uint32_t epoch, const Node& start,
                      size_t chain_idx, size_t start_pos, size_t steps) {
  Node current = start;
  for (size_t i = 0; i < steps; ++i) {
    const uint64_t position = static_cast<uint64_t>(start_pos + i + 1);
    current = hash_chain(param, epoch, current,
                         static_cast<uint64_t>(chain_idx), position);
  }
  return current;
}

Node hash_tree_node(const Bytes& param, const Node& left, const Node& right,
                    uint32_t level, uint32_t index) {
  return sha256_node(build_tree_hash(param, left, right, level, index));
}

Node hash_public_key(const Bytes& param, uint32_t epoch,
                     const std::vector<Node>& pk_hashes) {
  return sha256_node(build_public_key_hash(param, epoch, pk_hashes));
}

}
