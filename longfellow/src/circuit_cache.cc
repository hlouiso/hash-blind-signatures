#include "circuit_cache.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "proto/circuit_io.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zstd.h"

namespace blind_longfellow {
namespace {

using proofs::Circuit;
using proofs::CircuitReader;
using proofs::CircuitWriter;
using proofs::ReadBuffer;

constexpr proofs::FieldID kFieldID = proofs::GF2_128_ID;

constexpr int kZstdLevel = 16;

constexpr char kMagic[4] = {'B', 'L', 'F', 'C'};

constexpr uint8_t kFormatVersion = 7;
constexpr size_t kHeaderLen = sizeof(kMagic) + 1;

}

const char* default_circuit_cache_path() {
#ifdef BL_CIRCUIT_CACHE
  return BL_CIRCUIT_CACHE;
#else
  return "circuit.cache";
#endif
}

void save_circuit(const Field& F, const Circuit<Field>& circuit,
                  const std::string& path) {

  std::vector<uint8_t> raw;
  CircuitWriter<Field> writer(F, kFieldID);
  writer.to_bytes(circuit, raw);

  const size_t bound = ZSTD_compressBound(raw.size());
  std::vector<uint8_t> comp(bound);
  const size_t zl =
      ZSTD_compress(comp.data(), bound, raw.data(), raw.size(), kZstdLevel);
  if (ZSTD_isError(zl)) {
    throw std::runtime_error(std::string("save_circuit: ZSTD_compress: ") +
                             ZSTD_getErrorName(zl));
  }
  comp.resize(zl);
  proofs::log(proofs::INFO, "circuit cache: %zu -> %zu bytes (zstd)",
              raw.size(), zl);

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("save_circuit: cannot open: " + path);
  f.write(kMagic, sizeof(kMagic));
  const char ver = static_cast<char>(kFormatVersion);
  f.write(&ver, 1);
  f.write(reinterpret_cast<const char*>(comp.data()),
          static_cast<std::streamsize>(comp.size()));
  if (!f) throw std::runtime_error("save_circuit: write failed: " + path);
}

std::unique_ptr<Circuit<Field>> load_circuit(const Field& F,
                                             const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return nullptr;
  const std::vector<uint8_t> file{std::istreambuf_iterator<char>(f),
                                  std::istreambuf_iterator<char>()};

  if (file.size() < kHeaderLen) return nullptr;
  if (std::memcmp(file.data(), kMagic, sizeof(kMagic)) != 0) return nullptr;
  if (file[sizeof(kMagic)] != kFormatVersion) return nullptr;

  const uint8_t* comp = file.data() + kHeaderLen;
  const size_t comp_len = file.size() - kHeaderLen;

  const unsigned long long raw_len = ZSTD_getFrameContentSize(comp, comp_len);
  if (raw_len == ZSTD_CONTENTSIZE_ERROR || raw_len == ZSTD_CONTENTSIZE_UNKNOWN) {
    return nullptr;
  }

  std::vector<uint8_t> raw(static_cast<size_t>(raw_len));
  const size_t got = ZSTD_decompress(raw.data(), raw.size(), comp, comp_len);
  if (ZSTD_isError(got) || got != raw.size()) return nullptr;

  ReadBuffer rb(raw.data(), raw.size());
  CircuitReader<Field> reader(F, kFieldID);
  return reader.from_bytes(rb,  true);
}

std::unique_ptr<Circuit<Field>> build_or_load_circuit(
    const Field& F, const Elt pow_x[kBits128], const std::string& path,
    bool* cache_hit) {
  if (auto cached = load_circuit(F, path)) {
    if (cache_hit) *cache_hit = true;
    proofs::log(proofs::INFO, "circuit cache: hit (%s)", path.c_str());
    return cached;
  }
  if (cache_hit) *cache_hit = false;
  auto circuit = build_circuit(F, pow_x);
  save_circuit(F, *circuit, path);
  return circuit;
}

}
