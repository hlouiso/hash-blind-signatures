#include "protocol.hpp"
#include <iostream>
using namespace voleith;

static void require(bool ok, const char* text) {
  if (!ok) throw std::runtime_error(text);
}

template <class F>
static void rejects(F fn, const char* text) {
  bool rejected = false;
  try {
    fn();
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  require(rejected, text);
}

int main() try {
  Bytes message{'a', 'b', 'c'};
  auto signer = Signer::generate(2);
  auto pk = signer.public_key();
  auto state = commit(message);
  auto response0 = signer.sign(state.commitment);
  auto response = signer.sign(state.commitment);
  require(response0.leaf_index == 0 && response.leaf_index == 1,
          "leaf counter");
  require(encode(decode_secret(encode(signer.secret_key()))) ==
              encode(signer.secret_key()),
          "key serialization");
  require(encode(decode_public(encode(pk))) == encode(pk),
          "public key serialization");
  require(encode(decode_state(encode(state))) == encode(state),
          "user state serialization");
  require(encode(decode_response(encode(response))) == encode(response),
          "response serialization");
  require(encode(decode_commitment(encode(state.commitment))) ==
              encode(state.commitment),
          "commitment serialization");
  auto malformed = encode(pk);
  malformed.push_back(0);
  rejects([&] { decode_public(malformed); }, "trailing public key byte");
  malformed = encode(signer.secret_key());
  malformed[56] = 0;
  rejects([&] { decode_secret(malformed); }, "height zero");
  malformed = encode(signer.secret_key());
  malformed[57] = 5;
  rejects([&] { decode_secret(malformed); }, "out-of-range leaf counter");
  rejects([&] { decode_state(encode(state.commitment)); },
          "artifact type confusion");
  malformed = encode(response);
  malformed.pop_back();
  rejects([&] { decode_response(malformed); }, "truncated response");

  Statement stmt{state.digest, pk.seed, pk.root};
  auto primary = primary_witness(state, pk, response);
  auto bad_native = [&](Bytes bad) {
    rejects(
        [&] {
          NativeContext e(bad);
          Circuit c(e);
          c.statement(stmt);
        },
        "invalid witness accepted");
  };
  for (size_t offset :
       {size_t(0), 96ul, kSigOffset, kSigOffset + 4, kSigOffset + 28,
        kSigOffset + 28 + 42 * 16, kEndpointsOffset}) {
    auto bad = primary;
    bad[offset] ^= 1;
    bad_native(bad);
  }
  for (uint8_t index : {42, 63, 64, 128, 255}) {
    auto invalid = primary;
    invalid[kScheduleOffset] = index;
    bad_native(invalid);
  }
  auto bad = primary;
  std::reverse(bad.begin() + kScheduleOffset, bad.begin() + kEndpointsOffset);
  bad_native(bad);
  bad = primary;
  std::fill(bad.begin() + kScheduleOffset, bad.begin() + kEndpointsOffset,
            primary[kScheduleOffset]);
  bad_native(bad);
  auto bad_state = state;
  bad_state.r[0] ^= 1;
  rejects([&] { primary_witness(bad_state, pk, response); },
          "inconsistent opening");
  auto bad_response = response;
  bad_response.auth_path[0][0] ^= 1;
  rejects([&] { primary_witness(state, pk, bad_response); },
          "invalid native signature");

  auto proof = unblind(state, pk, response);
  require(verify_signature(pk, message, proof), "round trip");
  auto proof2 = unblind(state, pk, response);
  require(proof != proof2 && verify_signature(pk, message, proof2),
          "fresh randomized proofs");
  auto wrong_message = message;
  wrong_message[0] ^= 1;
  require(!verify_signature(pk, wrong_message, proof), "message binding");
  auto wrong_pk = pk;
  wrong_pk.root[0] ^= 1;
  require(!verify_signature(wrong_pk, message, proof), "root binding");
  wrong_pk = pk;
  wrong_pk.seed[0] ^= 1;
  require(!verify_signature(wrong_pk, message, proof), "public seed binding");
  auto l = proof_layout();
  for (size_t offset : {size_t(0), size_t(8), size_t(9), size_t(10), l.nonce,
                        l.commitment, l.vole_check, l.correction, l.quicksilver,
                        l.opening, l.delta, l.size - 1}) {
    auto altered = proof;
    altered[offset] ^= 1;
    require(!verify(stmt, altered), "altered proof accepted");
  }
  if constexpr (kGrindingBits > 0) {
    auto altered = proof;
    altered[l.delta + 15] |= 0x80;
    require(!verify(stmt, altered), "grinding target not enforced");
    altered = proof;
    altered[l.counter] ^= 1;
    require(!verify(stmt, altered), "grinding counter not bound");
  }
  for (size_t length : {size_t(0), size_t(8), l.commitment, l.correction,
                        l.opening, l.size - 1})
    require(!verify(stmt, std::span(proof).first(length)),
            "truncated proof accepted");
  auto longer = proof;
  longer.push_back(0);
  require(!verify(stmt, longer), "trailing proof byte accepted");
  bool failed = false;
  try {
    signer.sign(state.commitment, [](const SecretKey&) {
      throw std::runtime_error("disk failure");
    });
  } catch (const std::runtime_error&) {
    failed = true;
  }
  require(failed && signer.secret_key().next_leaf == 3,
          "failed reservation reused leaf");
  auto last = signer.sign(state.commitment);
  require(last.leaf_index == 3, "last leaf");
  bool exhausted = false;
  try {
    signer.sign(state.commitment);
  } catch (const std::runtime_error&) {
    exhausted = true;
  }
  require(exhausted, "exhausted key accepted");
  auto empty = commit({});
  auto small = Signer::generate(1);
  auto small_pk = small.public_key();
  auto empty_proof = unblind(empty, small_pk, small.sign(empty.commitment));
  require(verify_signature(small_pk, {}, empty_proof), "empty message");
  std::cout << "Protocol, malformed-proof, witness, serialization and state "
               "tests passed\n";
} catch (const std::exception& e) {
  std::cerr << e.what() << '\n';
  return 1;
}
