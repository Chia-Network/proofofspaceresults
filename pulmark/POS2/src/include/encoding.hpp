// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ENCODING_HPP_
#define ENCODING_HPP_

#include <cmath>
#include <map>
#include <queue>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bits.hpp"
#include "fpc.h"
#include "fse.h"
#include "hist.h"
// #include "r16N.h"
#include "util.hpp"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif

constexpr int kFPCBlockSize = 32 * 1024;

/**
 * @brief The iEncoder class - interface class for compression/decompression
 */
class iEncoder {
public:
  virtual ~iEncoder() {}

  virtual uint128_t SquareToLinePoint(uint64_t x, uint64_t y) = 0;
  virtual std::pair<uint64_t, uint64_t> LinePointToSquare(uint128_t index) = 0;

  virtual ParkBits ANSEncodeDeltas(std::vector<unsigned char> deltas,
                                   double R) = 0;

  virtual std::vector<uint8_t> ANSDecodeDeltas(Bits bits, size_t numDeltas,
                                               double R) = 0;
  virtual std::vector<uint8_t> ANSDecodeDeltas(ParkBits bits, size_t numDeltas,
                                               double R) = 0;
  virtual std::vector<uint8_t> ANSDecodeDeltas(LargeBits bits, size_t numDeltas,
                                               double R) = 0;
};

/**
 * @brief The EncoderBase class
 */
class EncoderBase : public iEncoder {
public:
  ~EncoderBase() override {
#ifndef NDEBUG
    if (encode_stats_.second > 0)
      std::cout << "* Encoder compress ratio: " << std::fixed
                << std::setprecision(3)
                << ((encode_stats_.second * 100.0) / encode_stats_.first)
                << " %" << std::endl;
#endif
  }

  // Encodes two max k bit values into one max 2k bit value. This can be thought
  // of mapping points in a two dimensional space into a one dimensional space.
  // The benefits of this are that we can store these line points efficiently,
  // by sorting them, and only storing the differences between them.
  // Representing numbers as pairs in two dimensions limits the compression
  // strategies that can be used. The x and y here represent table positions in
  // previous tables.
  inline uint128_t SquareToLinePoint(uint64_t x, uint64_t y) override {
    // Always makes y < x, which maps the random x, y  points from a square into
    // a triangle. This means less data is needed to represent y, since we know
    // it's less than x.
    if (y > x) {
      std::swap(x, y);
    }
    return ((uint128_t)x * (uint128_t)(x - 1)) / 2 + y;
  }

  // Does the opposite as the above function, deterministicaly mapping a one
  // dimensional line point into a 2d pair. However, we do not recover the
  // original ordering here.
  inline std::pair<uint64_t, uint64_t>
  LinePointToSquare(uint128_t index) override {
    // Performs a square root, without the use of doubles, to use the precision
    // of the uint128_t.
    uint64_t x = 0;
    for (int8_t i = 63; i >= 0; i--) {
      uint64_t new_x = x + ((uint64_t)1 << i);
      if ((uint128_t)new_x * (new_x - 1) / 2 <= index)
        x = new_x;
    }
    return std::pair<uint64_t, uint64_t>(x, index -
                                                (((uint128_t)x * (x - 1)) / 2));
  }

#ifndef NDEBUG
  std::pair<double, double> encode_stats_{0, 0};
#endif
};

/**
 * @brief The FPCEncoder class - Fast Prefix Compress/Decompress
 */
class FPCEncoder : public EncoderBase {

public:
  FPCEncoder(size_t bufSize = 2 * kMaxSizeBits) : bufSize_{bufSize} {
    out_ = std::make_unique<uint8_t[]>(bufSize);
    inp_ = std::make_unique<uint8_t[]>(bufSize);
  }

  ~FPCEncoder() override {}

  inline ParkBits ANSEncodeDeltas(std::vector<unsigned char> deltas,
                                  [[maybe_unused]] double R) override {
    m_assert(deltas.size() <= bufSize_, "deltas size too big for compression");
    auto cnt =
        FPC_compress(out_.get(), &deltas[0], deltas.size(), kFPCBlockSize);
    m_assert(cnt <= kParkVectorBytes, "compressed size too big");

#ifndef NDEBUG
    encode_stats_.first += deltas.size();
    encode_stats_.second += cnt;
#endif
    ParkBits res = ParkBits(out_.get(), cnt, cnt * 8);
    return res;
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(Bits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(ParkBits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(LargeBits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

private:
  // byte buffers for internal use
  const size_t bufSize_;
  std::unique_ptr<uint8_t[]> out_;
  std::unique_ptr<uint8_t[]> inp_;

  /**
   * @brief decode
   * @param bits
   * @param numDeltas
   * @param R
   * @return
   */
  template <typename T>
  std::vector<uint8_t> decodeT(T &bits, size_t numDeltas) {
    assert(bufSize_ >= (numDeltas * 8));
    auto inpsize = Util::ByteAlign(static_cast<T>(bits).GetSize()) / 8;
    static_cast<T>(bits).ToBytes(reinterpret_cast<uint8_t *>(inp_.get()));

    size_t cnt = FPC_decompress(out_.get(), numDeltas, inp_.get(), inpsize);
    m_assert(cnt <= numDeltas, "decoded size too big");
    std::vector<uint8_t> deltas(out_.get(), out_.get() + numDeltas);
#ifdef TEST
    // valitidy check
    for (auto i = 0u; i < deltas.size(); i++) {
      if (deltas[i] == 0xff) {
        throw std::runtime_error("Bad delta detected");
      }
    }
#endif
    return deltas;
  }
};

/**
 * @brief The FSEEncoder class - Finite State Entropy Compress/Decompress.
 */
class FSEEncoder : public EncoderBase {

public:
  FSEEncoder(size_t bufSize = kMaxSizeBits * 2)
      : bufSize_{bufSize}, out_{std::make_unique<uint8_t[]>(bufSize)},
        inp_{std::make_unique<uint8_t[]>(bufSize)} {}

  ~FSEEncoder() override {
    // release FSE resources
    for (auto k : dt_)
      FSE_freeDTable(k.second);
    for (auto k : ct_)
      FSE_freeCTable(k.second);
  }

  inline ParkBits ANSEncodeDeltas(std::vector<unsigned char> deltas,
                                  double R) override {
    FSE_CTable *table = nullptr;
    auto it = ct_.find(R);
    if (it != ct_.end()) {
      table = it->second;
    } else {
      auto nCount = createNormalizedCount(R);
      auto maxSymbolValue = nCount.size() - 1;
      auto tableLog = 14;
      if (maxSymbolValue > 255)
        return ParkBits();
      table = FSE_createCTable(maxSymbolValue, tableLog);
      size_t err =
          FSE_buildCTable(table, nCount.data(), maxSymbolValue, tableLog);
      if (FSE_isError(err)) {
        FSE_freeCTable(table);
        throw FSE_getErrorName(err);
      }
      ct_[R] = table;
    }

    assert(bufSize_ >= (deltas.size() * 8));
    auto num_bytes = FSE_compress_usingCTable(
        out_.get(), deltas.size() * 8, static_cast<void *>(deltas.data()),
        deltas.size(), table);

#ifndef NDEBUG
    encode_stats_.first += deltas.size();
    encode_stats_.second += num_bytes;
#endif
    ParkBits res = ParkBits(out_.get(), num_bytes, num_bytes * 8);
    return res;
  }

  inline std::vector<uint8_t> ANSDecodeDeltas(Bits bits, size_t numDeltas,
                                              double R) override {
    return decodeT(bits, numDeltas, R);
  }

  inline std::vector<uint8_t> ANSDecodeDeltas(ParkBits bits, size_t numDeltas,
                                              double R) override {
    return decodeT(bits, numDeltas, R);
  }

  inline std::vector<uint8_t> ANSDecodeDeltas(LargeBits bits, size_t numDeltas,
                                              double R) override {
    return decodeT(bits, numDeltas, R);
  }

private:
  // FSE compress/decompress tables
  std::unordered_map<double, FSE_CTable *> ct_;
  std::unordered_map<double, FSE_DTable *> dt_;
  // byte buffers for internal use
  size_t bufSize_;
  std::unique_ptr<uint8_t[]> out_;
  std::unique_ptr<uint8_t[]> inp_;

  /**
   * @brief CreateNormalizedCount
   * @param R
   * @return
   */
  inline std::vector<short> createNormalizedCount(double R) {
    std::vector<double> dpdf;
    int N = 0;
    double E = 2.718281828459;
    double MIN_PRB_THRESHOLD = 1e-50;
    int TOTAL_QUANTA = 1 << 14;
    double p = 1 - pow((E - 1) / E, 1.0 / R);

    while (p > MIN_PRB_THRESHOLD && N < 255) {
      dpdf.push_back(p);
      N++;
      p = (pow(E, 1.0 / R) - 1) * pow(E - 1, 1.0 / R);
      p /= pow(E, ((N + 1) / R));
    }

    std::vector<short> ans(N, 1);
    auto cmp = [&dpdf, &ans](int i, int j) {
      return dpdf[i] * (log2(ans[i] + 1) - log2(ans[i])) <
             dpdf[j] * (log2(ans[j] + 1) - log2(ans[j]));
    };

    std::priority_queue<int, std::vector<int>, decltype(cmp)> pq(cmp);
    for (int i = 0; i < N; ++i)
      pq.push(i);

    for (int todo = 0; todo < TOTAL_QUANTA - N; ++todo) {
      int i = pq.top();
      pq.pop();
      ans[i]++;
      pq.push(i);
    }

    for (int i = 0; i < N; ++i) {
      if (ans[i] == 1) {
        ans[i] = (short)-1;
      }
    }
    return ans;
  }

  /**
   * @brief decode
   * @param bits
   * @param numDeltas
   * @param R
   * @return
   */
  template <typename T>
  std::vector<uint8_t> decodeT(T &bits, size_t numDeltas, double R) {
    assert(bufSize_ >= (numDeltas * 8));

    FSE_DTable *table = nullptr;
    auto it = dt_.find(R);
    if (it != dt_.end()) {
      table = it->second;
    } else {
      auto nCount = createNormalizedCount(R);
      auto maxSymbolValue = nCount.size() - 1;
      auto tableLog = 14U;

      table = FSE_createDTable(tableLog);
      size_t err =
          FSE_buildDTable(table, nCount.data(), maxSymbolValue, tableLog);
      if (FSE_isError(err)) {
        FSE_freeCTable(table);
        throw FSE_getErrorName(err);
      }
      dt_[R] = table;
    }
    assert(table != nullptr);

    std::memset(inp_.get(), 0x00, numDeltas * 8);
    int inpsize = Util::ByteAlign(static_cast<T>(bits).GetSize()) / 8;
    std::memset(out_.get(), 0x00, numDeltas);
    static_cast<T>(bits).ToBytes(reinterpret_cast<uint8_t *>(inp_.get()));
    auto err = FSE_decompress_usingDTable(out_.get(), numDeltas, inp_.get(),
                                          inpsize, table);
    if (FSE_isError(err)) {
      throw FSE_getErrorName(err);
    }
    std::vector<uint8_t> deltas(out_.get(), out_.get() + numDeltas);
#ifdef TEST
    // delta valitidy check
    for (uint32_t i = 0; i < deltas.size(); i++) {
      if (deltas[i] == 0xff) {
        throw std::runtime_error("Bad delta detected");
      }
    }
#endif
    return deltas;
  }
};

#if 0
/**
 * @brief The rANSEncoder class - rANS static compress/decompress
 */
class rANSEncoder : public EncoderBase {

public:
  rANSEncoder(unsigned int bufSize = kMaxSizeBits * 2) : bufSize_{bufSize} {
    out_ = std::make_unique<uint8_t[]>(bufSize);
    inp_ = std::make_unique<uint8_t[]>(bufSize);
  }

  ~rANSEncoder() override {}

  inline ParkBits ANSEncodeDeltas(std::vector<unsigned char> deltas,
                                  [[maybe_unused]] double R) override {
    auto cnt = bufSize_;
    m_assert(deltas.size() <= bufSize_, "deltas size too big for compression");

    uint32_t len = rans_compress_bound_4x16(kParkVectorBytes, 0, nullptr);
    m_assert(len <= bufSize_, "compressed size too big");
    uint8_t *ret = rans_compress_to_4x16(&deltas.front(), deltas.size(),
                                         out_.get(), &len, 0);
    m_assert(ret != nullptr, "compression failed, ret == NULL");
    m_assert(len <= kParkVectorBytes, "compressed size too big");

#ifndef NDEBUG
    encode_stats_.first += deltas.size();
    encode_stats_.second += len;
#endif
    ParkBits res(ret, len, len * 8);
    return res;
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(Bits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(ParkBits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

  inline std::vector<uint8_t>
  ANSDecodeDeltas(LargeBits bits, size_t numDeltas,
                  [[maybe_unused]] double R) override {
    return decodeT(bits, numDeltas);
  }

private:
  // byte buffers for internal use
  const unsigned int bufSize_;
  std::unique_ptr<uint8_t[]> out_;
  std::unique_ptr<uint8_t[]> inp_;

  /**
   * @brief decode
   * @param bits
   * @param numDeltas
   * @param R
   * @return
   */
  template <typename T>
  std::vector<uint8_t> decodeT(T &bits, size_t numDeltas) {
    m_assert(bufSize_ >= (numDeltas * 8),
             "number of deltas too big compared to buf");
    auto inpsize = Util::ByteAlign(static_cast<T>(bits).GetSize()) / 8;
    static_cast<T>(bits).ToBytes(reinterpret_cast<uint8_t *>(inp_.get()));
    auto cnt = bufSize_;
    uint8_t *ret =
        rans_uncompress_to_4x16(inp_.get(), inpsize, out_.get(), &cnt, 0);
    m_assert(ret != nullptr, "uncompress failed, res == NULL");
    m_assert(cnt <= numDeltas, "uncompressed len too big");
    std::vector<uint8_t> deltas(ret, ret + numDeltas);
#ifdef TEST
    // valitidy check
    for (auto i = 0u; i < deltas.size(); i++) {
      if (deltas[i] == 0xff) {
        throw std::runtime_error("Bad delta detected");
      }
    }
#endif
    return deltas;
  }
};
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#endif // ENCODING_HPP
