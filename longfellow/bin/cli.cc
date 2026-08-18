#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "circuit/blind_stmt.h"
#include "circuit_cache.h"
#include "field.h"
#include "protocol.h"
#include "rng.h"
#include "util/log.h"
#include "xmss.h"

namespace blind_longfellow {
namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open: " + path);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open: " + path);
  f.write(reinterpret_cast<const char*>(data.data()),
          static_cast<std::streamsize>(data.size()));
  if (!f) throw std::runtime_error("cannot write: " + path);
}

std::string hex(const uint8_t* p, size_t n) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(2 * n);
  for (size_t i = 0; i < n; ++i) {
    s += kDigits[p[i] >> 4];
    s += kDigits[p[i] & 0xf];
  }
  return s;
}

struct Options {
  std::string dir = ".";
  std::string cache;
  std::string msg_file;
  size_t height = kXmssHDefault;

  std::string path(const char* name) const { return dir + "/" + name; }
  std::string cache_path() const {
    return cache.empty() ? default_circuit_cache_path() : cache;
  }
};

void usage() {
  std::fprintf(stderr,
      "usage: blindsig <command> [options]\n"
      "\n"
      "commands:\n"
      "  keygen                signer:   generate an XMSS key pair\n"
      "  commit <msg_file>     user:     commit to a message (round 1)\n"
      "  sign                  signer:   sign the commitment (round 1 reply)\n"
      "  prove                 user:     build the blind signature (round 2)\n"
      "  verify <msg_file>     verifier: check the blind signature\n"
      "\n"
      "options:\n"
      "  -d, --dir <path>      directory holding the artefacts (default \".\")\n"
      "  --circuit-cache <p>   circuit cache file for prove/verify\n"
      "  --height <h>          real XMSS tree height (keygen only, default 10,\n"
      "                        max 32).  Keygen sweeps every one of the 2^h\n"
      "                        leaves and this CLI repeats that sweep on every\n"
      "                        invocation, so raising it costs time on both; the\n"
      "                        circuit climbs 32 levels either way.\n"
      "  -h, --help\n");
}

std::unique_ptr<proofs::Circuit<Field>> open_circuit(const Field& F,
                                                     const Options& opt) {
  Elt pow_x[kBits128];
  fill_pow_x(F, pow_x);
  const auto t0 = Clock::now();
  bool cache_hit = false;
  auto circuit = build_or_load_circuit(F, pow_x, opt.cache_path(), &cache_hit);
  std::printf("  circuit  : %s  %.0f ms  (%zu layers)\n",
              cache_hit ? "cache hit" : "compiled + cached", ms_since(t0),
              circuit->nl);
  return circuit;
}

int cmd_keygen(const Options& opt) {
  SecureRng rng;
  SignerKey key;
  rng.fill_bytes(key.sk_seed, kSkSeedBytes);
  rng.fill_bytes(key.pk_seed.data(), key.pk_seed.size());
  key.height = static_cast<uint8_t>(opt.height);
  key.next_leaf = 0;

  const auto t0 = Clock::now();
  const XmssKeyPair kp =
      XmssKeyPair::generate_from_seed(key.sk_seed, key.pk_seed, opt.height);
  const double keygen_ms = ms_since(t0);
  const Node root = kp.public_key();

  const auto key_bytes = write_signer_key(key);
  const auto pub_bytes = write_signer_pub(root, key.pk_seed);
  write_file(opt.path("signer_key.bin"), key_bytes);
  write_file(opt.path("signer_pub.bin"), pub_bytes);

  std::printf("keygen  ·  XMSS h=%zu (%llu one-time signatures)  %.0f ms\n",
              opt.height,
              static_cast<unsigned long long>(uint64_t{1} << opt.height),
              keygen_ms);
  std::printf("  root     : %s\n", hex(root.data(), root.size()).c_str());
  std::printf("  pk_seed  : %s\n",
              hex(key.pk_seed.data(), key.pk_seed.size()).c_str());
  std::printf("  → signer_key.bin (%zu B, secret)\n", key_bytes.size());
  std::printf("  → signer_pub.bin (%zu B)\n", pub_bytes.size());
  return 0;
}

int cmd_commit(const Options& opt) {
  const Bytes msg = read_file(opt.msg_file);

  const Field F;
  SecureRng rng;
  UserState state;
  const auto t0 = Clock::now();
  const HmCommitment com = user_commit(F, rng, msg, state);
  const double commit_ms = ms_since(t0);

  const auto com_bytes = write_commitment(com);
  const auto state_bytes = write_user_state(state);
  write_file(opt.path("commitment.bin"), com_bytes);
  write_file(opt.path("user_state.bin"), state_bytes);

  std::printf("commit  ·  message %zu B  %.1f ms\n", msg.size(), commit_ms);
  std::printf("  → commitment.bin (%zu B, send to the signer)\n",
              com_bytes.size());
  std::printf("  → user_state.bin (%zu B, secret)\n", state_bytes.size());
  return 0;
}

int cmd_sign(const Options& opt) {
  SignerKey key = read_signer_key(read_file(opt.path("signer_key.bin")));
  const HmCommitment com = read_commitment(read_file(opt.path("commitment.bin")));

  const uint64_t leaf = key.next_leaf;
  const auto t0 = Clock::now();
  const auto sig = signer_sign(key, com);
  const double sign_ms = ms_since(t0);
  if (!sig.has_value()) {
    std::fprintf(stderr, "sign: key exhausted\n");
    return 1;
  }

  const auto sig_bytes = write_xmss_sig(*sig);
  write_file(opt.path("xmss_sig.bin"), sig_bytes);
  write_file(opt.path("signer_key.bin"), write_signer_key(key));

  std::printf("sign  ·  leaf %llu of %llu  %.0f ms\n",
              static_cast<unsigned long long>(leaf),
              static_cast<unsigned long long>(uint64_t{1} << key.height), sign_ms);
  std::printf("  → xmss_sig.bin (%zu B, send to the user)\n", sig_bytes.size());
  std::printf("  signer_key.bin updated: next_leaf = %llu (%llu left)\n",
              static_cast<unsigned long long>(key.next_leaf),
              static_cast<unsigned long long>((uint64_t{1} << key.height) -
                                              key.next_leaf));
  return 0;
}

int cmd_prove(const Options& opt) {
  proofs::set_log_level(proofs::ERROR);
  const Field F;

  std::printf("prove  ·  Longfellow (Ligero + sumcheck over GF(2^128))\n");
  auto circuit = open_circuit(F, opt);

  const UserState state = read_user_state(read_file(opt.path("user_state.bin")));
  const auto [xmss_root, pk_seed] =
      read_signer_pub(read_file(opt.path("signer_pub.bin")));

  const Hash d = hm_com_digest(state.com);
  const auto parsed = read_xmss_sig(read_file(opt.path("xmss_sig.bin")),
                                    pk_seed, d.data(), d.size());
  if (!parsed.has_value()) {
    std::fprintf(stderr,
                 "prove: xmss_sig.bin is not a signature on this commitment "
                 "under signer_pub.bin\n");
    return 1;
  }

  if (parsed->root != xmss_root) {
    std::fprintf(stderr,
                 "prove: signature does not verify under signer_pub.bin "
                 "(recomputed root differs)\n");
    return 1;
  }

  const auto t0 = Clock::now();
  const BlindSignature bsig = user_prove(F, *circuit, state, *parsed);
  const double prove_ms = ms_since(t0);
  if (bsig.proof.empty()) {
    std::fprintf(stderr, "prove: prover failed (constraint violated?)\n");
    return 1;
  }

  const auto out_bytes = write_blind_sig(bsig);
  write_file(opt.path("blind_sig.bin"), out_bytes);
  std::printf("  → blind_sig.bin (%.1f KB)  %.0f ms\n",
              out_bytes.size() / 1024.0, prove_ms);
  return 0;
}

int cmd_verify(const Options& opt) {
  proofs::set_log_level(proofs::ERROR);
  const Field F;

  std::printf("verify  ·  Longfellow (Ligero + sumcheck over GF(2^128))\n");
  auto circuit = open_circuit(F, opt);

  const Bytes msg = read_file(opt.msg_file);
  const BlindSignature bsig = read_blind_sig(read_file(opt.path("blind_sig.bin")));
  const auto [xmss_root, pk_seed] =
      read_signer_pub(read_file(opt.path("signer_pub.bin")));

  const auto t0 = Clock::now();
  const bool ok = verify_blind_sig(F, *circuit, xmss_root, pk_seed, bsig, msg);
  const double verify_ms = ms_since(t0);

  std::printf("  [%s]  %.1f KB  %.0f ms\n", ok ? "PASS" : "FAIL",
              bsig.proof.size() / 1024.0, verify_ms);
  return ok ? 0 : 1;
}

int run(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 1;
  }
  const std::string cmd = argv[1];
  if (cmd == "-h" || cmd == "--help" || cmd == "help") {
    usage();
    return 0;
  }

  Options opt;
  std::vector<std::string> positional;
  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](const char* what) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (arg == "--height") {
      opt.height = static_cast<size_t>(std::stoul(next("--height")));
      if (opt.height < 1 || opt.height > kXmssH) {
        std::fprintf(stderr, "error: --height must be in 1..%zu\n", kXmssH);
        std::exit(1);
      }
    } else if (arg == "-d" || arg == "--dir") {
      opt.dir = next("--dir");
    } else if (arg == "--circuit-cache") {
      opt.cache = next("--circuit-cache");
    } else if (arg == "-h" || arg == "--help") {
      usage();
      return 0;
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown option: " + arg);
    } else {
      positional.push_back(arg);
    }
  }

  const bool needs_msg = (cmd == "commit" || cmd == "verify");
  if (needs_msg) {
    if (positional.size() != 1) {
      std::fprintf(stderr, "%s needs exactly one <msg_file>\n", cmd.c_str());
      return 1;
    }
    opt.msg_file = positional[0];
  } else if (!positional.empty()) {
    std::fprintf(stderr, "%s takes no positional arguments\n", cmd.c_str());
    return 1;
  }

  if (cmd == "keygen") return cmd_keygen(opt);
  if (cmd == "commit") return cmd_commit(opt);
  if (cmd == "sign") return cmd_sign(opt);
  if (cmd == "prove") return cmd_prove(opt);
  if (cmd == "verify") return cmd_verify(opt);

  std::fprintf(stderr, "unknown command: %s\n\n", cmd.c_str());
  usage();
  return 1;
}

}
}

int main(int argc, char** argv) {
  try {
    return blind_longfellow::run(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
