#include "protocol.hpp"
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

void usage() {
  std::cout
      << "usage: blindsig <keygen|commit|sign|prove|verify|params> "
         "[message_file] [-d directory] [--height h]\n"
      << "Default real XMSS height: 10. All proofs check a 32-level path.\n"
      << "Application hashes: SHAKE256; VOLE: GF(2^128), tau=" << kVoleTrees
      << ", degree=" << kProofDegree << ", grind=" << kGrindingBits << ".\n";
}
}

int main(int argc, char** argv) try {
  if (argc < 2) {
    usage();
    return 1;
  }
  std::string command = argv[1];
  fs::path dir = ".", message;
  int height = XMSS_H_DEFAULT;
  bool height_set = false;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if ((a == "-d" || a == "--dir") && i + 1 < argc)
      dir = argv[++i];
    else if (a == "--height" && i + 1 < argc) {
      std::string v = argv[++i];
      size_t used = 0;
      height = std::stoi(v, &used);
      if (used != v.size()) throw std::invalid_argument("invalid height");
      height_set = true;
    } else if (a == "-h" || a == "--help") {
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
  if (height_set && command != "keygen")
    throw std::invalid_argument("--height is for keygen only");
  auto start = std::chrono::steady_clock::now();
  if (command == "keygen") {
    fs::create_directories(dir);
    Lock lock(dir / "signer.lock");
    if (fs::exists(dir / "signer_key.bin") ||
        fs::exists(dir / "signer_pub.bin"))
      throw std::runtime_error(
          "key artifacts already exist; choose a new directory");
    auto signer = Signer::generate(height);
    write(dir / "signer_key.bin", encode(signer.secret_key()));
    write(dir / "signer_pub.bin", encode(signer.public_key()));
    std::cout << "XMSS height=" << height
              << " capacity=" << (uint64_t(1) << height) << '\n';
  } else if (command == "commit") {
    fs::create_directories(dir);
    auto state = commit(read(message));
    write(dir / "user_state.bin", encode(state));
    write(dir / "commitment.bin", encode(state.commitment));
  } else if (command == "sign") {
    Lock lock(dir / "signer.lock");
    auto com = decode_commitment(read(dir / "commitment.bin", 264));
    Signer signer(decode_secret(read(dir / "signer_key.bin", 65)));
    auto response = signer.sign(com, [&](const SecretKey& key) {
      write(dir / "signer_key.bin", encode(key));
    });
    write(dir / "xmss_sig.bin", encode(response));
    std::cout << "Consumed XMSS leaf " << response.leaf_index << '\n';
  } else if (command == "prove") {
    auto pk = decode_public(read(dir / "signer_pub.bin", 40));
    auto state = decode_state(read(dir / "user_state.bin", 392));
    auto response =
        decode_response(read(dir / "xmss_sig.bin", 8 + XMSS_SIG_BYTES));
    auto signature = unblind(state, pk, response);
    write(dir / "blind_sig.bin", signature);
    std::cout << "Blind signature: " << signature.size() << " bytes\n";
  } else if (command == "verify") {
    auto pk = decode_public(read(dir / "signer_pub.bin", 40));
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
