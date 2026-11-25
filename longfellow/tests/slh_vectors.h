/* A minimal JSON reader for the shared SLH-DSA test vectors in
 * ../test-vectors/slh/ (objects, arrays, strings without escapes, integers
 * and null), plus hex decoding. Test-only. */

#ifndef BLIND_LONGFELLOW_TESTS_SLH_VECTORS_H_
#define BLIND_LONGFELLOW_TESTS_SLH_VECTORS_H_

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace blind_longfellow {
namespace testvec {

struct Json {
  enum Kind { kNull, kStr, kNum, kArr, kObj } kind = kNull;
  std::string str;
  long long num = 0;
  std::vector<Json> arr;
  std::vector<std::pair<std::string, Json>> obj;

  bool is_null() const { return kind == kNull; }
  const Json& operator[](const std::string& key) const {
    for (const auto& kv : obj)
      if (kv.first == key) return kv.second;
    throw std::runtime_error("JSON: missing key " + key);
  }
};

class JsonParser {
 public:
  explicit JsonParser(std::string text) : s_(std::move(text)) {}
  Json parse() {
    Json v = value();
    ws();
    if (i_ != s_.size()) fail("trailing data");
    return v;
  }

 private:
  [[noreturn]] void fail(const char* what) {
    throw std::runtime_error(std::string("JSON: ") + what + " at " +
                             std::to_string(i_));
  }
  void ws() {
    while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_])))
      ++i_;
  }
  void expect(char c) {
    ws();
    if (i_ >= s_.size() || s_[i_] != c) fail("unexpected character");
    ++i_;
  }
  std::string string() {
    expect('"');
    std::string out;
    while (i_ < s_.size() && s_[i_] != '"') {
      if (s_[i_] == '\\') fail("escapes are not supported");
      out.push_back(s_[i_++]);
    }
    expect('"');
    return out;
  }
  Json value() {
    ws();
    if (i_ >= s_.size()) fail("unexpected end");
    Json v;
    const char c = s_[i_];
    if (c == '"') {
      v.kind = Json::kStr;
      v.str = string();
    } else if (c == '{') {
      v.kind = Json::kObj;
      ++i_;
      ws();
      if (s_[i_] == '}') {
        ++i_;
        return v;
      }
      for (;;) {
        std::string key = string();
        expect(':');
        v.obj.emplace_back(std::move(key), value());
        ws();
        if (s_[i_] == ',') {
          ++i_;
          continue;
        }
        expect('}');
        break;
      }
    } else if (c == '[') {
      v.kind = Json::kArr;
      ++i_;
      ws();
      if (s_[i_] == ']') {
        ++i_;
        return v;
      }
      for (;;) {
        v.arr.push_back(value());
        ws();
        if (s_[i_] == ',') {
          ++i_;
          continue;
        }
        expect(']');
        break;
      }
    } else if (s_.compare(i_, 4, "null") == 0) {
      i_ += 4;
    } else if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      size_t used = 0;
      v.kind = Json::kNum;
      v.num = std::stoll(s_.substr(i_), &used);
      i_ += used;
    } else {
      fail("unsupported value");
    }
    return v;
  }
  std::string s_;
  size_t i_ = 0;
};

inline Json load_json(const std::string& path) {
  std::ifstream f(path);
  if (!f) throw std::runtime_error("cannot open " + path);
  return JsonParser(std::string(std::istreambuf_iterator<char>(f), {})).parse();
}

inline std::vector<uint8_t> unhex(const std::string& h) {
  if (h.size() % 2) throw std::runtime_error("odd hex length");
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("bad hex digit");
  };
  std::vector<uint8_t> out(h.size() / 2);
  for (size_t i = 0; i < out.size(); ++i)
    out[i] = static_cast<uint8_t>(16 * nib(h[2 * i]) + nib(h[2 * i + 1]));
  return out;
}

template <size_t N>
std::array<uint8_t, N> unhex_array(const std::string& h) {
  const auto v = unhex(h);
  if (v.size() != N) throw std::runtime_error("hex field has the wrong length");
  std::array<uint8_t, N> out;
  std::copy(v.begin(), v.end(), out.begin());
  return out;
}

}  // namespace testvec
}  // namespace blind_longfellow

#endif
