#include "protocol.hpp"
#include "slh_protocol.hpp"
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

using namespace voleith;
namespace fs = std::filesystem;

namespace {
Bytes read(const fs::path& path, size_t limit = SIZE_MAX) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) throw std::runtime_error("cannot open " + path.string());
  auto size = f.tellg();
  if (size < 0 || static_cast<uintmax_t>(size) > limit)
    throw std::runtime_error("invalid file length: " + path.string());
  Bytes b(static_cast<size_t>(size));
  f.seekg(0);
  if (!b.empty() && !f.read(reinterpret_cast<char*>(b.data()), b.size()))
    throw std::runtime_error("cannot read " + path.string());
  return b;
}

// The rename and fsync complete before a reserved XMSS leaf can be released.
// A stable sidecar lock coordinates processes despite replacement of the key.
void write(const fs::path& path, std::span<const uint8_t> b) {
  auto tmp = (path.string() + ".tmp.XXXXXX");
  int fd = mkstemp(tmp.data());
  if (fd < 0) throw std::runtime_error("cannot create temporary artifact");
  bool closed = false;
  try {
    size_t at = 0;
    while (at < b.size()) {
      auto n = ::write(fd, b.data() + at, b.size() - at);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) throw std::runtime_error("artifact write failed");
      at += n;
    }
    if (fsync(fd) != 0) throw std::runtime_error("artifact fsync failed");
    const auto result = close(fd);
    closed = true;
    if (result != 0 || rename(tmp.c_str(), path.c_str()) != 0)
      throw std::runtime_error("artifact replacement failed");
    int dirfd = open(path.parent_path().c_str(), O_RDONLY);
    if (dirfd < 0) throw std::runtime_error("cannot open artifact directory");
    const auto synced = fsync(dirfd);
    close(dirfd);
    if (synced != 0) throw std::runtime_error("directory fsync failed");
  } catch (...) {
    if (!closed) close(fd);
    unlink(tmp.c_str());
    throw;
  }
}

struct Lock {
  int fd;

  explicit Lock(const fs::path& path)
      : fd(open(path.c_str(), O_CREAT | O_RDWR, 0600)) {
    if (fd < 0) throw std::runtime_error("cannot open signer lock");
    if (flock(fd, LOCK_EX) != 0) {
      close(fd);
      throw std::runtime_error("cannot lock signer state");
    }
  }

  ~Lock() {
    flock(fd, LOCK_UN);
    close(fd);
  }
};

// The stateful scheme fixes the XMSS height at the XMSS_H levels the circuit
// checks; a key file of any other height was not made by this keygen.
void require_fixed_height(int height, const char* file) {
  if (height != XMSS_H)
    throw std::runtime_error(std::string(file) + " has XMSS height " +
                             std::to_string(height) + "; keys have height " +
                             std::to_string(XMSS_H) + ", run keygen again");
}

void usage() {
  std::cout
      << "usage: blindsig <keygen|commit|sign|prove|verify|params> "
         "[message_file] [-d directory] [--stateful|--stateless]\n"
      << "keygen --stateful (the default) puts XMSS of height " << XMSS_H
      << " underneath,\n2^" << XMSS_H
      << " one-time signatures (the lifetime of SLH-DSA-128-24): each signature\n"
         "consumes a leaf and sign rewrites signer_key.bin; keygen sweeps all the\n"
         "leaves, a few minutes on 8 cores. keygen --stateless\n"
         "puts SLH-DSA-SHAKE-128-24 underneath: sign never rewrites the key. The\n"
         "other commands follow the scheme recorded in the key files. In both\n"
         "schemes keygen also writes signer_cache.bin, the upper levels of the\n"
         "signer's tree, so that sign rebuilds one small subtree instead of the\n"
         "whole key; without it, sign rebuilds the key and rewrites the cache.\n"
      << "Application hashes: SHAKE256; VOLE: GF(2^128), tau=" << kVoleTrees
      << ", degree=" << kProofDegree << ", grind=" << kGrindingBits << ".\n";
}

const slh_params& kStateless = kSlhShake128_24;

// signer_cache.bin: the upper levels of the signer's tree, so that sign
// rebuilds one small subtree rather than the whole key. Framed like the other
// artefacts ("HBVO001", kind 'X' for XMSS or 'L' for SLH-DSA), then a header,
// the levels from the bottom one up and a 32-byte tag, SHAKE256 under the
// secret seed of everything before it, which ties the cache to its key. The
// XMSS header is height || split, the SLH-DSA header set || first. A missing
// or invalid cache only costs time: sign rebuilds the tree and writes a fresh
// cache.
constexpr char kCacheMagic[] = "HBVO001";
constexpr uint8_t kCacheDomain[] = "blindsig-voleith/signer-cache/v1";
constexpr size_t kCacheTagBytes = 32;

std::array<uint8_t, kCacheTagBytes> cache_tag(std::span<const uint8_t> secret,
                                              std::span<const uint8_t> body) {
  Bytes m(secret.begin(), secret.end());
  m.insert(m.end(), body.begin(), body.end());
  std::array<uint8_t, kCacheTagBytes> tag;
  shake_th(kCacheDomain, sizeof(kCacheDomain) - 1, m.data(), m.size(), tag.data(),
           tag.size());
  return tag;
}

Bytes cache_file(char kind, std::array<uint8_t, 2> header, std::span<const uint8_t> nodes,
                 std::span<const uint8_t> secret) {
  Bytes b(kCacheMagic, kCacheMagic + 7);
  b.push_back(static_cast<uint8_t>(kind));
  b.insert(b.end(), header.begin(), header.end());
  b.insert(b.end(), nodes.begin(), nodes.end());
  const auto tag = cache_tag(secret, b);
  b.insert(b.end(), tag.begin(), tag.end());
  return b;
}

struct Cache {
  std::array<uint8_t, 2> header;
  Bytes nodes;
};

std::optional<Cache> read_cache(const fs::path& dir, char kind,
                                std::span<const uint8_t> secret) {
  const auto path = dir / "signer_cache.bin";
  std::error_code ec;
  if (!fs::exists(path, ec)) return std::nullopt;
  const Bytes b = read(path, size_t{64} << 20);
  if (b.size() < 10 + kCacheTagBytes || memcmp(b.data(), kCacheMagic, 7) != 0 ||
      b[7] != static_cast<uint8_t>(kind))
    return std::nullopt;
  const size_t body = b.size() - kCacheTagBytes;
  const auto tag = cache_tag(secret, std::span(b).first(body));
  if (!std::equal(tag.begin(), tag.end(), b.begin() + body)) return std::nullopt;
  return Cache{{b[8], b[9]}, Bytes(b.begin() + 10, b.begin() + body)};
}

const char* tree_source(bool from_cache) {
  return from_cache ? "from signer_cache.bin"
                    : "rebuilt (no valid signer_cache.bin), cache written";
}

// signer_pub.bin tells the user and the verifier which scheme the signer has.
bool stateless_pub(const fs::path& dir, Bytes& pub, const char* who) {
  if (!fs::exists(dir / "signer_pub.bin"))
    throw std::runtime_error(std::string(who) +
                             " needs signer_pub.bin, which records the "
                             "signer's scheme; run keygen first");
  pub = read(dir / "signer_pub.bin", 64);
  return artifact_kind(pub) == 'p';
}

Bytes read_state(const fs::path& dir, bool stateless) {
  auto state = read(dir / "user_state.bin", 400);
  if ((artifact_kind(state) == 'u') != stateless)
    throw std::runtime_error(
        std::string("user_state.bin was committed for the ") +
        (stateless ? "stateful (XMSS)" : "stateless (SLH-DSA)") +
        " scheme but signer_pub.bin is " +
        (stateless ? "stateless (SLH-DSA)" : "stateful (XMSS)") +
        "; run commit again");
  return state;
}
}

int main(int argc, char** argv) try {
  if (argc < 2) {
    usage();
    return 1;
  }
  std::string command = argv[1];
  fs::path dir = ".", message;
  int scheme = 0;  // 0 unset, 1 stateful, 2 stateless
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if ((a == "-d" || a == "--dir") && i + 1 < argc)
      dir = argv[++i];
    else if (a == "--stateful" || a == "--stateless") {
      const int s = a == "--stateful" ? 1 : 2;
      if (scheme != 0 && scheme != s)
        throw std::invalid_argument("--stateful and --stateless are mutually exclusive");
      scheme = s;
    }
    else if (a == "-h" || a == "--help") {
      usage();
      return 0;
    } else if (!a.starts_with('-') && message.empty())
      message = a;
    else
      throw std::invalid_argument("unknown or incomplete argument: " + a);
  }
  if (command == "--help" || command == "-h") {
    usage();
    return 0;
  }
  const bool has_message = command == "commit" || command == "verify";
  if (has_message == message.empty())
    throw std::invalid_argument(
        "message file required only for commit and verify");
  if (scheme != 0 && command != "keygen")
    throw std::invalid_argument("--stateful and --stateless are keygen options; " +
                                command + " follows the key files");
  auto start = std::chrono::steady_clock::now();
  if (command == "keygen") {
    fs::create_directories(dir);
    Lock lock(dir / "signer.lock");
    if (fs::exists(dir / "signer_key.bin") ||
        fs::exists(dir / "signer_pub.bin"))
      throw std::runtime_error(
          "key artifacts already exist; choose a new directory");
    if (scheme == 2) {
      const auto signer = SlhSigner::generate(kStateless);
      const auto sk = signer.secret_key();
      write(dir / "signer_key.bin", encode_slh(kStateless, sk));
      write(dir / "signer_pub.bin", encode_slh(kStateless, signer.public_key()));
      write(dir / "signer_cache.bin",
            cache_file('L', {1, static_cast<uint8_t>(signer.top_first())},
                       signer.top_cache(), sk.sk_seed));
      std::cout << kStateless.name << " (stateless) capacity=" << (uint64_t(1) << 24)
                << '\n';
      std::cout << command << ": "
                << std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
                       .count()
                << " s\n";
      return 0;
    }
    const int height = XMSS_H;
    auto signer = Signer::generate_cached(height);
    write(dir / "signer_key.bin", encode(signer.secret_key()));
    write(dir / "signer_pub.bin", encode(signer.public_key()));
    write(dir / "signer_cache.bin",
          cache_file('X',
                     {static_cast<uint8_t>(height),
                      static_cast<uint8_t>(signer.subtree_height())},
                     signer.top_cache(), signer.secret_key().seed));
    std::cout << "XMSS height=" << height
              << " capacity=" << (uint64_t(1) << height) << '\n';
  } else if (command == "commit") {
    Bytes pub;
    if (stateless_pub(dir, pub, "commit")) {
      auto state = slh_commit(read(message));
      write(dir / "user_state.bin", encode_slh(state));
      write(dir / "commitment.bin", encode(state.commitment));
    } else {
      auto state = commit(read(message));
      write(dir / "user_state.bin", encode(state));
      write(dir / "commitment.bin", encode(state.commitment));
    }
  } else if (command == "sign" &&
             artifact_kind(read(dir / "signer_key.bin", 128)) == 'k') {
    // A stateless key is never rewritten, so signing needs no lock.
    auto com = decode_commitment(read(dir / "commitment.bin", 264));
    const auto sk = decode_slh_secret(kStateless, read(dir / "signer_key.bin", 128));
    std::optional<SlhSigner> cached = [&]() -> std::optional<SlhSigner> {
      if (auto c = read_cache(dir, 'L', sk.sk_seed); c && c->header[0] == 1)
        return SlhSigner::from_cache(kStateless, sk, c->header[1], c->nodes);
      return std::nullopt;
    }();
    const bool from_cache = cached.has_value();
    const SlhSigner signer = from_cache ? std::move(*cached) : SlhSigner(kStateless, sk);
    const auto sig = signer.sign(com);
    std::array<uint8_t, 32> d;
    slh_com_digest(com.data(), d.data());
    if (!slh_verify(&kStateless, sk.pk_seed.data(), sk.pk_root.data(), d.data(), d.size(),
                    sig.data(), sig.size()))
      throw std::runtime_error(
          "the signature does not verify (deleting signer_cache.bin makes sign rebuild it)");
    if (!from_cache)
      write(dir / "signer_cache.bin",
            cache_file('L', {1, static_cast<uint8_t>(signer.top_first())}, signer.top_cache(),
                       sk.sk_seed));
    write(dir / "slh_sig.bin", encode_slh_response(kStateless, sig));
    std::cout << "Stateless " << kStateless.name
              << " signature; signer_key.bin unchanged; top tree " << tree_source(from_cache)
              << '\n';
  } else if (command == "sign") {
    Lock lock(dir / "signer.lock");
    auto com = decode_commitment(read(dir / "commitment.bin", 264));
    const auto sk = decode_secret(read(dir / "signer_key.bin", 65));
    require_fixed_height(sk.height, "signer_key.bin");
    if (sk.next_leaf == (uint64_t(1) << sk.height))
      throw std::runtime_error("XMSS key exhausted");
    std::optional<Signer> cached;
    if (auto c = read_cache(dir, 'X', sk.seed); c && c->header[0] == sk.height)
      cached = Signer::from_cache(sk, c->header[1], c->nodes);
    const bool from_cache = cached.has_value();
    Signer signer =
        from_cache ? std::move(*cached) : Signer(sk, xmss_cache_split_height(sk.height));
    if (!from_cache)
      write(dir / "signer_cache.bin",
            cache_file('X',
                       {static_cast<uint8_t>(sk.height),
                        static_cast<uint8_t>(signer.subtree_height())},
                       signer.top_cache(), sk.seed));
    auto response = signer.sign(com, [&](const SecretKey& key) {
      write(dir / "signer_key.bin", encode(key));
    });
    write(dir / "xmss_sig.bin", encode(response));
    std::cout << "Consumed XMSS leaf " << response.leaf_index << '\n';
    std::cout << "XMSS tree " << tree_source(from_cache) << '\n';
  } else if (command == "prove") {
    Bytes pub;
    const bool stateless = stateless_pub(dir, pub, "prove");
    const auto state_bytes = read_state(dir, stateless);
    if (stateless) {
      const auto pk = decode_slh_public(kStateless, pub);
      const auto state = decode_slh_state(state_bytes);
      const auto sig = decode_slh_response(
          kStateless, read(dir / "slh_sig.bin", 16 + slh_sig_bytes(&kStateless)));
      auto signature = slh_unblind(kStateless, state, pk, sig);
      write(dir / "blind_sig.bin", signature);
      std::cout << "Blind signature: " << signature.size() << " bytes\n";
      std::cout << command << ": "
                << std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
                       .count()
                << " s\n";
      return 0;
    }
    auto pk = decode_public(pub);
    require_fixed_height(pk.height, "signer_pub.bin");
    auto state = decode_state(state_bytes);
    auto response =
        decode_response(read(dir / "xmss_sig.bin", 8 + XMSS_SIG_BYTES));
    auto signature = unblind(state, pk, response);
    write(dir / "blind_sig.bin", signature);
    std::cout << "Blind signature: " << signature.size() << " bytes\n";
  } else if (command == "verify") {
    Bytes pub;
    if (stateless_pub(dir, pub, "verify")) {
      const auto pk = decode_slh_public(kStateless, pub);
      if (!slh_verify_signature(
              kStateless, pk, read(message),
              read(dir / "blind_sig.bin", slh_proof_layout(kStateless).size))) {
        std::cerr << "[FAIL]\n";
        return 1;
      }
      std::cout << "[PASS]\n";
      std::cout << command << ": "
                << std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
                       .count()
                << " s\n";
      return 0;
    }
    auto pk = decode_public(pub);
    require_fixed_height(pk.height, "signer_pub.bin");
    if (!verify_signature(pk, read(message),
                          read(dir / "blind_sig.bin", proof_layout().size))) {
      std::cerr << "[FAIL]\n";
      return 1;
    }
    std::cout << "[PASS]\n";
  } else if (command == "params") {
    std::cout << "Witness: " << kWitnessBits / 8
              << " bytes; constraints: " << kConstraints
              << "; Keccak permutations: " << kPermutations
              << "; proof: " << proof_layout().size << " bytes\n";
    const SlhDims dims = slh_proof_dims(kStateless);
    std::cout << "Stateless (" << kStateless.name << ") witness: " << dims.witness_bits / 8
              << " bytes; constraints: " << dims.constraints
              << "; Keccak permutations: " << dims.permutations
              << "; proof: " << slh_proof_layout(kStateless).size << " bytes\n";
  } else {
    usage();
    return 1;
  }
  std::cout << command << ": "
            << std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                             start)
                   .count()
            << " s\n";
  return 0;
} catch (const std::exception& e) {
  std::cerr << "error: " << e.what() << '\n';
  return 1;
}
