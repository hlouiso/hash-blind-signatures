// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Adapted from Longfellow ZK's lib/proto/circuit_writer.h and
// circuit_reader.h at 1424f50e. The only change is the width of every
// serialized count and index: four bytes instead of CircuitIO::kBytesPerSizeT
// = 3. The SLH-DSA-SHA2-128-24 circuit has a layer with more than 2^24 - 1
// terms, which the upstream format cannot store. The version byte is 0x84 so
// that neither reader accepts the other's files. The in-memory Circuit is
// unchanged; only the cache file differs.

#ifndef BLIND_LONGFELLOW_SLH_WIDE_CIRCUIT_IO_H_
#define BLIND_LONGFELLOW_SLH_WIDE_CIRCUIT_IO_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "proto/circuit_io.h"
#include "sumcheck/circuit.h"
#include "sumcheck/circuit_id.h"
#include "sumcheck/quad.h"
#include "sumcheck/quad_builder.h"
#include "util/ceildiv.h"
#include "util/panic.h"
#include "util/readbuffer.h"

namespace blind_longfellow {
namespace slh {

struct WideCircuitIO {
  static constexpr size_t kBytesPerSizeT = 4;
  static constexpr uint8_t kVersion = 0x84;
  static constexpr uint64_t kMaxValue = (1ULL << (kBytesPerSizeT * 8)) - 1;
};

template <class Field>
class WideCircuitWriter {
  using Elt = typename Field::Elt;
  using QuadCorner = typename proofs::Quad<Field>::quad_corner_t;

 public:
  WideCircuitWriter(const Field& f, proofs::FieldID field_id)
      : f_(f), field_id_(field_id) {}

  void to_bytes(const proofs::Circuit<Field>& c, std::vector<uint8_t>& bytes) {
    proofs::KvecBuilder<Field> kb(f_);
    for (const auto& layer : c.l)
      for (const auto& ec : *layer.quad) kb.kstore(ec.v);

    bytes.push_back(WideCircuitIO::kVersion);
    num(bytes, static_cast<size_t>(field_id_));
    num(bytes, c.nv);
    num(bytes, c.nc);
    num(bytes, c.npub_in);
    num(bytes, c.subfield_boundary);
    num(bytes, c.ninputs);
    num(bytes, c.l.size());

    auto kvec = kb.kvec();
    num(bytes, kvec->size());
    for (const auto& v : *kvec) {
      uint8_t buf[Field::kBytes];
      f_.to_bytes_field(buf, v);
      bytes.insert(bytes.end(), buf, buf + Field::kBytes);
    }

    for (const auto& layer : c.l) {
      num(bytes, layer.logw);
      num(bytes, layer.nw);
      num(bytes, layer.quad->size());
      QuadCorner prevg(0), prevh0(0), prevh1(0);
      for (const auto& ec : *layer.quad) {
        index(bytes, ec.g, prevg);
        index(bytes, ec.h[0], prevh0);
        index(bytes, ec.h[1], prevh1);
        num(bytes, kb.kload(ec.v));
        prevg = ec.g;
        prevh0 = ec.h[0];
        prevh1 = ec.h[1];
      }
    }
    bytes.insert(bytes.end(), c.id, c.id + proofs::CircuitIO::kIdSize);
  }

 private:
  static void index(std::vector<uint8_t>& bytes, QuadCorner i, QuadCorner prev) {
    const size_t a = static_cast<size_t>(i), b = static_cast<size_t>(prev);
    num(bytes, a >= b ? 2u * (a - b) : 2u * (b - a) + 1u);
  }

  static void num(std::vector<uint8_t>& bytes, size_t g) {
    proofs::check(g <= WideCircuitIO::kMaxValue, "wide circuit writer: value too large");
    for (size_t i = 0; i < WideCircuitIO::kBytesPerSizeT; ++i) {
      bytes.push_back(static_cast<uint8_t>(g & 0xff));
      g >>= 8;
    }
  }

  const Field& f_;
  proofs::FieldID field_id_;
};

// The files are written locally by the prover and verifier and so trusted;
// as upstream, the reader performs only basic sanity checks, and optionally
// recomputes the circuit id.
template <class Field, class Input = proofs::ReadBuffer>
class WideCircuitReader {
  using Elt = typename Field::Elt;
  using QuadCorner = typename proofs::Quad<Field>::quad_corner_t;

 public:
  WideCircuitReader(const Field& f, proofs::FieldID field_id)
      : f_(f), field_id_(field_id) {}

  std::unique_ptr<proofs::Circuit<Field>> from_bytes(Input& buf,
                                                     bool enforce_circuit_id) {
    std::unique_ptr<proofs::Circuit<Field>> c;
    std::shared_ptr<std::vector<Elt>> constants;
    if (!read_header(buf, c, constants)) return nullptr;
    if (!read_layers(buf, c->nl, c->nv, constants->size(), constants, *c))
      return nullptr;
    if (!buf.have(proofs::CircuitIO::kIdSize)) return nullptr;
    buf.next(proofs::CircuitIO::kIdSize, c->id);
    if (enforce_circuit_id) {
      uint8_t idtmp[proofs::CircuitIO::kIdSize];
      proofs::circuit_id(idtmp, *c, f_);
      if (std::memcmp(idtmp, c->id, proofs::CircuitIO::kIdSize) != 0) return nullptr;
    }
    return c;
  }

 private:
  static constexpr size_t kMaxValidWireId = 0xFFFFFFFEull;
  static constexpr size_t kMaxValidIndex = 0xFFFFFFFFull;
  static constexpr size_t kW = WideCircuitIO::kBytesPerSizeT;

  bool read_header(Input& buf,
                   std::unique_ptr<proofs::Circuit<Field>>& c,
                   std::shared_ptr<std::vector<Elt>>& constants) {
    if (!buf.have(8 * kW + 1)) return false;
    if (*buf.next(1) != WideCircuitIO::kVersion) return false;
    const size_t fid = num(buf), nv = num(buf), nc = num(buf), npub_in = num(buf),
                 subfield_boundary = num(buf), ninputs = num(buf), nl = num(buf),
                 numconst = num(buf);
    if (nv == 0 || nv > kMaxValidWireId || nc == 0 || nl == 0 ||
        nl > proofs::CircuitIO::kMaxLayers || fid != static_cast<size_t>(field_id_) ||
        ninputs > kMaxValidWireId || npub_in > ninputs ||
        subfield_boundary > ninputs || numconst > kMaxValidIndex)
      return false;
    auto need = proofs::CircuitIO::checked_mul(numconst, Field::kBytes);
    if (!need || !buf.have(need.value())) return false;
    constants = std::make_shared<std::vector<Elt>>(numconst);
    for (size_t i = 0; i < numconst; ++i) {
      auto vv = f_.of_bytes_field(buf.next(Field::kBytes));
      if (!vv.has_value()) return false;
      (*constants)[i] = vv.value();
    }
    c = std::make_unique<proofs::Circuit<Field>>();
    *c = proofs::Circuit<Field>{
        .nv = nv,
        .logv = proofs::lg(nv),
        .nc = nc,
        .logc = proofs::lg(nc),
        .nl = nl,
        .ninputs = ninputs,
        .npub_in = npub_in,
        .subfield_boundary = subfield_boundary,
    };
    c->l.reserve(nl);
    return true;
  }

  bool read_layers(Input& buf, size_t nl, size_t nv, size_t numconst,
                   const std::shared_ptr<std::vector<Elt>>& constants,
                   proofs::Circuit<Field>& c) {
    size_t max_g = nv;
    proofs::ApproximateDeltaTableBuilder<Field> db(/*prime*/ 8209);
    for (size_t ly = 0; ly < nl; ++ly) {
      if (!buf.have(3 * kW)) return false;
      const size_t lw = num(buf);
      if (lw > proofs::LayerProof<Field>::kMaxBindings || !(lw > 0)) return false;
      const size_t nw = num(buf);
      if (!(nw > 0) || nw < lw || nw > kMaxValidWireId || nw > (1ull << lw))
        return false;
      const size_t nq = num(buf);
      if (!(nq > 0) || nq > kMaxValidIndex) return false;
      auto need = proofs::CircuitIO::checked_mul(4 * kW, nq);
      if (!need || !buf.have(need.value())) return false;
      auto qq = std::make_unique<proofs::Quad<Field>>(nq, constants, db.delta_table());
      size_t prevg = 0, prevhl = 0, prevhr = 0;
      for (size_t i = 0; i < nq; ++i) {
        const uint8_t* term = buf.next(4 * kW);
        const size_t g = index(term, prevg);
        if (g >= max_g) return false;
        const size_t hl = index(term + kW, prevhl), hr = index(term + 2 * kW, prevhr);
        if (hl >= nw || hr >= nw) return false;
        const size_t vi = decode(term + 3 * kW);
        if (vi >= numconst) return false;
        qq->assign(i, db.dedup(QuadCorner(g - prevg), QuadCorner(hl - prevhl),
                               QuadCorner(hr - prevhr), static_cast<uint32_t>(vi)));
        prevg = g;
        prevhl = hl;
        prevhr = hr;
      }
      c.l.push_back(proofs::Layer<Field>{
          .nw = nw,
          .logw = lw,
          .quad = std::unique_ptr<const proofs::Quad<Field>>(std::move(qq))});
      max_g = nw;
    }
    return true;
  }

  static size_t index(const uint8_t* p, size_t prev) {
    const size_t delta = decode(p);
    return (delta & 1) ? prev - (delta >> 1) : prev + (delta >> 1);
  }

  static size_t num(Input& buf) { return decode(buf.next(kW)); }

  static size_t decode(const uint8_t* p) {
    uint64_t r = 0;
    for (size_t i = 0; i < kW; ++i) r |= static_cast<uint64_t>(p[i]) << (8 * i);
    return static_cast<size_t>(r);
  }

  const Field& f_;
  proofs::FieldID field_id_;
};

}  // namespace slh
}  // namespace blind_longfellow

#endif
