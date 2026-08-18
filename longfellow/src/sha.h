/* Domain-separated SHA-256 formats (integer fields are little-endian):
 * message = pk_seed || 02 || epoch || nonce || message;
 * chain   = pk_seed || 00 || epoch || node || chain || position;
 * leaf    = pk_seed || 01 || epoch || WOTS endpoints;
 * tree    = (pk_seed || 03 || zero padding) || level || index || left || right.
 * Internal nodes truncate SHA-256 to 128 bits. */

#ifndef BLIND_LONGFELLOW_SHA_H_
#define BLIND_LONGFELLOW_SHA_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace blind_longfellow {

constexpr size_t kHashBytes = 32;

constexpr size_t kNodeBytes = 16;
constexpr size_t kNodeBits = 8 * kNodeBytes;
constexpr size_t kNodeFieldLimbs = (kNodeBits + 127) / 128;
constexpr size_t kPkSeedBytes = 16;
constexpr size_t kNonceLength = 24;

constexpr size_t kEpochBytes = 4;

using Hash = std::array<uint8_t, kHashBytes>;
using Node = std::array<uint8_t, kNodeBytes>;
using PkSeed = std::array<uint8_t, kPkSeedBytes>;
using Bytes = std::vector<uint8_t>;

constexpr uint8_t kChainTweak = 0x00;
constexpr uint8_t kTreeTweak = 0x01;
constexpr uint8_t kMessageTweak = 0x02;
constexpr uint8_t kNodeTweak = 0x03;

constexpr size_t kTreePrefixBytes = 64;

using Midstate = std::array<uint32_t, 8>;

Hash sha256(const uint8_t* data, size_t n);
inline Hash sha256(const Bytes& v) { return sha256(v.data(), v.size()); }

Hash hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data,
                 size_t data_len);
inline Hash hmac_sha256(const Hash& key, const Bytes& data) {
  return hmac_sha256(key.data(), key.size(), data.data(), data.size());
}

Node sha256_node(const uint8_t* data, size_t n);
inline Node sha256_node(const Bytes& v) { return sha256_node(v.data(), v.size()); }

Bytes build_wots_domain_param(const PkSeed& pk_seed);

Bytes build_message_hash(const Bytes& param, uint32_t epoch,
                         const uint8_t* nonce, size_t nonce_len,
                         const uint8_t* message, size_t message_len);
Bytes build_chain_hash(const Bytes& param, uint32_t epoch, const Node& hash,
                       uint64_t chain_idx, uint64_t position);
Bytes build_tree_hash(const Bytes& param, const Node& left, const Node& right,
                      uint32_t level, uint32_t index);
Bytes build_public_key_hash(const Bytes& param, uint32_t epoch,
                            const std::vector<Node>& pk_hashes);

Bytes build_tree_prefix(const Bytes& param);

Midstate tree_midstate(const Bytes& param);

Hash hash_message(const Bytes& param, uint32_t epoch, const uint8_t* nonce,
                  size_t nonce_len, const uint8_t* message, size_t message_len);

Node hash_chain(const Bytes& param, uint32_t epoch, const Node& hash,
                uint64_t chain_idx, uint64_t position);

Node hash_chain_multi(const Bytes& param, uint32_t epoch, const Node& start,
                      size_t chain_idx, size_t start_pos, size_t steps);

Node hash_tree_node(const Bytes& param, const Node& left, const Node& right,
                    uint32_t level, uint32_t index);

Node hash_public_key(const Bytes& param, uint32_t epoch,
                     const std::vector<Node>& pk_hashes);

}

#endif
