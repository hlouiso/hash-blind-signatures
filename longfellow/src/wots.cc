#include "wots.h"

namespace blind_longfellow {

std::vector<uint8_t> extract_coords(const uint8_t* hash, bool* leftover_ok) {
  std::vector<uint8_t> coords;
  coords.reserve(kLen);
  for (size_t i = 0; i < kLen; ++i) {
    const size_t pos = coord_bit_pos(i);
    uint8_t c = 0;
    for (size_t k = 0; k < 3; ++k) {
      const size_t j = pos + k;
      c |= static_cast<uint8_t>(((hash[j / 8] >> (j % 8)) & 1u) << k);
    }
    coords.push_back(c);
  }
  if (leftover_ok != nullptr) {
    *leftover_ok = ((hash[7] >> 7) | (hash[15] >> 7)) == 0;
  }
  return coords;
}

GrindResult grind_nonce(const WinternitzSpec& spec, Rng& rng,
                        const Bytes& param, uint32_t epoch,
                        const uint8_t* message, size_t message_len) {
  Bytes nonce(kNonceLength, 0);
  for (;;) {
    rng.fill_bytes(nonce.data(), nonce.size());
    const Hash h = hash_message(param, epoch, nonce.data(), nonce.size(),
                                message, message_len);
    bool leftover_ok = false;
    std::vector<uint8_t> coords = extract_coords(h.data(), &leftover_ok);
    if (!leftover_ok) continue;
    uint64_t sum = 0;
    for (uint8_t c : coords) sum += c;
    if (sum == spec.target_sum) {
      Bytes tweaked = build_message_hash(param, epoch, nonce.data(),
                                         nonce.size(), message, message_len);
      return GrindResult{std::move(tweaked), std::move(coords), nonce};
    }
  }
}

std::vector<Node> compute_wots_pk_hashes(const Bytes& param, uint32_t epoch,
                                         const std::vector<Node>& sig_hashes,
                                         const std::vector<uint8_t>& coords) {
  const uint32_t chain_len = static_cast<uint32_t>(kW);
  std::vector<Node> pk;
  pk.reserve(sig_hashes.size());
  for (size_t i = 0; i < sig_hashes.size(); ++i) {
    const size_t coord = coords[i];
    const size_t remaining = (chain_len - 1) - coord;
    if (remaining == 0) {
      pk.push_back(sig_hashes[i]);
    } else {
      pk.push_back(
          hash_chain_multi(param, epoch, sig_hashes[i], i, coord, remaining));
    }
  }
  return pk;
}

std::vector<Node> generate_wots_secret_key(Rng& rng) {
  std::vector<Node> sk(kLen);
  for (Node& val : sk) rng.fill_bytes(val.data(), val.size());
  return sk;
}

std::vector<Node> compute_wots_public_key(const Bytes& param, uint32_t epoch,
                                          const std::vector<Node>& sk) {
  std::vector<Node> pk;
  pk.reserve(sk.size());
  for (size_t i = 0; i < sk.size(); ++i) {
    pk.push_back(hash_chain_multi(param, epoch, sk[i], i, 0, kMaxSteps));
  }
  return pk;
}

std::vector<Node> compute_wots_signature(const Bytes& param, uint32_t epoch,
                                         const std::vector<Node>& sk,
                                         const std::vector<uint8_t>& coords) {
  std::vector<Node> sig;
  sig.reserve(sk.size());
  for (size_t i = 0; i < sk.size(); ++i) {
    const size_t coord = coords[i];
    if (coord == 0) {
      sig.push_back(sk[i]);
    } else {
      sig.push_back(hash_chain_multi(param, epoch, sk[i], i, 0, coord));
    }
  }
  return sig;
}

WotsSigningData WotsSigningData::generate(const WinternitzSpec& spec, Rng& rng,
                                          Bytes domain_param, uint32_t epoch,
                                          const uint8_t* message,
                                          size_t message_len) {
  GrindResult grind =
      grind_nonce(spec, rng, domain_param, epoch, message, message_len);

  Hash message_hash = hash_message(domain_param, epoch, grind.nonce.data(),
                                   grind.nonce.size(), message, message_len);

  std::vector<Node> sig_hashes(kLen);
  for (Node& sig : sig_hashes) rng.fill_bytes(sig.data(), sig.size());

  std::vector<Node> pk_hashes =
      compute_wots_pk_hashes(domain_param, epoch, sig_hashes, grind.coords);

  WotsSigningData data;
  data.domain_param = std::move(domain_param);
  data.epoch = epoch;
  data.nonce = std::move(grind.nonce);
  data.coords = std::move(grind.coords);
  data.sig_hashes = std::move(sig_hashes);
  data.pk_hashes = std::move(pk_hashes);
  data.tweaked_message = std::move(grind.tweaked_message);
  data.message_hash = message_hash;
  return data;
}

}
