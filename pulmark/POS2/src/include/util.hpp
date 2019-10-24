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

#ifndef UTIL_HPP
#define UTIL_HPP

#include <algorithm>
#include <bitset>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

// #define VCL_NAMESPACE vcl
// #include "vectorclass.h"

// __uint128_t is only available in 64 bit architectures and on certain
// compilers.
using uint128_t = __uint128_t;
using int128_t = __int128_t;

// Allows printing of uint128_t
std::ostream &operator<<(std::ostream &strm, uint128_t const &v) {
  strm << "uint128(" << (uint64_t)(v >> 64) << ","
       << (uint64_t)(v & (((uint128_t)1 << 64) - 1)) << ")";
  return strm;
}

// Allows printing of msg together with assert condition fail
#ifdef NDEBUG
#define m_assert(Expr, Msg) ;
#else
#define m_assert(Expr, Msg) __m_assert(#Expr, Expr, __FILE__, __LINE__, Msg)
void __m_assert(const char *expr_str, bool expr, const char *file, int line,
                const char *msg) {
  if (!expr) {
    std::cerr << "Assert failed:\t" << msg << "\n"
              << "Expected:\t" << expr_str << "\n"
              << "Source:\t\t" << file << ", line " << line << "\n";
    abort();
  }
}
#endif

namespace Util {

template <typename X> static inline X Mod(X i, X n) { return (i % n + n) % n; }

// function to convert all standard types to 8-bit byte vector
template <typename T> static inline std::vector<std::byte> ToByte(T input) {
  std::byte *bytePointer = reinterpret_cast<std::byte *>(&input);
  return std::vector<std::byte>(bytePointer, bytePointer + sizeof(T));
}

static inline uint32_t ByteAlign(uint32_t num_bits) {
  return (num_bits + (8 - ((num_bits) % 8)) % 8);
}

static inline std::string HexStr(const uint8_t *data, size_t len) {
  std::stringstream s;
  s << std::hex;
  for (size_t i = 0; i < len; ++i)
    s << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  s << std::dec;
  return s.str();
}

/*
 * Converts a 32 bit int to bytes.
 */
static inline void IntToFourBytes(uint8_t *result, const uint32_t input) {
#ifndef USE_BIT_FIDDLING
  auto p = static_cast<const uint8_t *>(static_cast<const void *>(&input));
  std::reverse_copy(p, p + sizeof input, result);
#else
  for (size_t i = 0; i < 4; i++) {
    result[3 - i] = (input >> (i * 8));
  }
#endif
}

/*
 * Converts a 64 bit int to bytes.
 */
static inline void IntToEightBytes(uint8_t *result, const uint64_t input) {
#ifndef USE_BIT_FIDDLING
  auto p = static_cast<const uint8_t *>(static_cast<const void *>(&input));
  std::reverse_copy(p, p + sizeof input, result);
#else
  for (size_t i = 0; i < 8; i++) {
    result[7 - i] = (input >> (i * 8));
  }
#endif
}

/*
 * Converts a byte array to a 32 bit int.
 */
static inline uint32_t FourBytesToInt(const uint8_t *bytes) {
#ifndef USE_BIT_FIDDLING
  return __builtin_bswap32(
      *(reinterpret_cast<uint32_t *>(const_cast<uint8_t *>(bytes))));
#else
  uint32_t sum = 0;
  for (size_t i = 0; i < 4; i++) {
    uint32_t addend = (uint64_t)bytes[i] << (8 * (3 - i));
    sum |= addend;
  }
  return sum;
#endif
}

/*
 * Converts a byte array to a 64 bit int.
 */
static inline uint64_t EightBytesToInt(const uint8_t *bytes) {
#ifndef USE_BIT_FIDDLING
  return __builtin_bswap64(
      *(reinterpret_cast<uint64_t *>(const_cast<uint8_t *>(bytes))));
#else
  uint64_t sum = 0;
  for (size_t i = 0; i < 8; i++) {
    uint64_t addend = (uint64_t)bytes[i] << (8 * (7 - i));
    sum |= addend;
  }
  return sum;
#endif
}

static inline uint8_t GetSizeBits(uint128_t value) {
  uint8_t count = 0;
  while (value) {
    count++;
    value >>= 1;
  }
  return count;
}

static inline uint64_t SliceInt64FromBytes(const uint8_t *bytes,
                                           const uint32_t bytes_len,
                                           const uint32_t start_bit,
                                           const uint32_t num_bits) {
  assert(Util::ByteAlign(start_bit + num_bits) <= bytes_len * 8);
  assert(num_bits > 0 && num_bits <= 64);

  uint64_t sum = 0;
  uint32_t taken_bits = 0;

  uint32_t curr_byte = start_bit / 8;
  if (start_bit / 8 != (start_bit + num_bits) / 8) {
    sum += bytes[curr_byte] & ((1 << (8 - (start_bit % 8))) - 1);
    taken_bits += (8 - (start_bit % 8));
    ++curr_byte;
  } else {
    // Start and end bits are in the same byte
    return (uint64_t)((bytes[curr_byte] & ((1 << (8 - (start_bit % 8))) - 1)) >>
                      (8 - (start_bit % 8) - num_bits));
  }

  const uint32_t end_byte = ((start_bit + num_bits) / 8);
  for (; curr_byte < end_byte; ++curr_byte) {
    sum <<= 8;
    taken_bits += 8;
    sum += bytes[curr_byte];
  }
  if (taken_bits < num_bits) {
    sum <<= (num_bits - taken_bits);
    sum += (bytes[curr_byte] >> (8 - (num_bits - taken_bits)));
  }

  return sum;
}

static inline uint128_t SliceInt128FromBytes(const uint8_t *bytes,
                                             const uint32_t bytes_len,
                                             const uint32_t start_bit,
                                             const uint32_t num_bits) {
  assert(Util::ByteAlign(start_bit + num_bits) <= bytes_len * 8);

  uint128_t sum = 0;
  uint32_t taken_bits = 0;

  uint32_t curr_byte = start_bit / 8;
  if (start_bit / 8 != (start_bit + num_bits) / 8) {
    sum += (uint128_t)(bytes[curr_byte] & ((1 << (8 - (start_bit % 8))) - 1));
    taken_bits += (8 - (start_bit % 8));
    ++curr_byte;
  } else {
    // Start and end bits are in the same byte
    return (uint128_t)(
        (bytes[curr_byte] & ((1 << (8 - (start_bit % 8))) - 1)) >>
        (8 - (start_bit % 8) - num_bits));
  }

  const uint32_t end_byte = ((start_bit + num_bits) / 8);
  for (; curr_byte < end_byte; ++curr_byte) {
    sum <<= 8;
    taken_bits += 8;
    sum += bytes[curr_byte];
  }
  if (taken_bits < num_bits) {
    sum <<= (num_bits - taken_bits);
    sum += (uint128_t)(bytes[curr_byte] >> (8 - (num_bits - taken_bits)));
  }
  return sum;
}

static inline void EntryToBytes(uint128_t *entries, uint32_t start_pos,
                                uint32_t end_pos, uint8_t last_size,
                                uint8_t buffer[]) {
  uint8_t shift = Util::ByteAlign(last_size) - last_size;
  uint128_t val = entries[end_pos - 1] << (shift);
  uint16_t cnt = 0;
  uint8_t iterations = last_size / 8;
  if (last_size % 8)
    iterations++;
  for (uint8_t i = 0; i < iterations; i++) {
    buffer[cnt++] = (val & 0xff);
    val >>= 8;
  }

  if (end_pos - start_pos >= 2) {
    for (int32_t i = end_pos - 2; i >= (int32_t)start_pos; i--) {
      uint128_t val = entries[i];
      for (uint8_t j = 0; j < 16; j++) {
        buffer[cnt++] = (val & 0xff);
        val >>= 8;
      }
    }
  }
  std::reverse(buffer, buffer + cnt);
}

/*
 * Given an array of bytes, extracts an unsigned 64 bit integer from the given
 * index, to the given index.
 */
static inline uint64_t ExtractNum(const uint8_t *bytes, uint64_t len_bytes,
                                  uint64_t begin_bits, uint64_t take_bits) {

  uint64_t start_index = begin_bits / 8;
  uint64_t end_index;
  if ((begin_bits + take_bits) / 8 > len_bytes - 1) {
    take_bits = (len_bytes * 8) - begin_bits;
  }
  end_index = (begin_bits + take_bits) / 8;
  assert(take_bits <= 64);

  uint64_t sum = bytes[start_index] & ((1 << (8 - (begin_bits % 8))) - 1);
  for (auto i = start_index + 1; i <= end_index; i++) {
    sum = (sum << 8) + bytes[i];
  }
  return sum >> (8 - ((begin_bits + take_bits) % 8));
}

}; // namespace Util

inline void process_mem_usage(double &vm_usage, double &resident_set) {
  vm_usage = 0.0;
  resident_set = 0.0;

  // the two fields we want
  unsigned long vsize;
  long rss;
  {
    std::string ignore;
    std::ifstream ifs("/proc/self/stat", std::ios_base::in);
    ifs >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >>
        ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >>
        ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >>
        ignore >> vsize >> rss;
  }

  long page_size_kb = sysconf(_SC_PAGE_SIZE) /
                      1024; // in case x86-64 is configured to use 2MB pages
  vm_usage = vsize / 1024.0;
  resident_set = rss * page_size_kb;
}

struct BitSet64 {
  std::bitset<64> bs;

  void init(const uint8_t *bytes, int cnt) {
    uint64_t num{0};
    // reverse or not ?
    for (int i = 0; i < cnt; i++)
      num = (num << 8) | bytes[i];
    bs = std::bitset<64>(num);
    //    std::cout << "bitset.init: bs = " << bs << std::endl;
  }

  uint64_t extract(size_t pos, size_t len) {
    std::bitset<64> mask = std::bitset<64>((uint64_t(1) << len) - 1);
    //    std::cout << "bitset.extract: " << std::endl;
    //    std::cout << "pos = " << pos << ", len = " << len << std::endl;
    //    std::cout << "mask = " << mask << std::endl;
    bs = mask & (bs >> pos);
    //    std::cout << "bs = " << bs << std::endl;
    uint64_t ret = bs.to_ullong();
    //    std::cout << "ret = " << ret << std::endl;
    return ret;
  }
};

class TimedSection {
  char const *name_;
  timespec wall_time_;
  timespec cpu_time_;

public:
  TimedSection(char const *name) : name_(name) {
    ::clock_gettime(CLOCK_REALTIME, &wall_time_);
    ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_time_);
  }
  ~TimedSection() {
    timespec wall_end;
    timespec cpu_end;
    ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end);
    ::clock_gettime(CLOCK_REALTIME, &wall_end);

    double duration_wall = 1e3 * (wall_end.tv_sec - wall_time_.tv_sec) +
                           1e-6 * (wall_end.tv_nsec - wall_time_.tv_nsec);
    double duration_cpu = 1e3 * (cpu_end.tv_sec - cpu_time_.tv_sec) +
                          1e-6 * (cpu_end.tv_nsec - cpu_time_.tv_nsec);
    double usage = (duration_cpu / duration_wall) * 100.0;

    std::stringstream ss;
    ss << name_ << ' ' << std::fixed << std::setprecision(3) << duration_wall;
    ss << " ms, CPU (" << std::fixed << std::setprecision(2) << usage
       << " %)\n";
    std::cout << ss.str();
  }
};

class Timer {
public:
  Timer() {
    this->wall_clock_time_start_ = std::chrono::steady_clock::now();
    this->cpu_time_start_ = clock();
  }

  void PrintElapsed(std::string name) {
    auto end = std::chrono::steady_clock::now();
    auto wall_clock_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             end - this->wall_clock_time_start_)
                             .count();

    double cpu_time_ms =
        1000.0 * (static_cast<double>(clock()) - this->cpu_time_start_) /
        CLOCKS_PER_SEC;

    double cpu_ratio =
        static_cast<int>(10000 * (cpu_time_ms / wall_clock_ms)) / 100.0;

    std::cout << name << " " << (wall_clock_ms / 1000.0) << " seconds. CPU ("
              << cpu_ratio << "%)" << std::endl;
  }

private:
  std::chrono::time_point<std::chrono::steady_clock> wall_clock_time_start_;
  clock_t cpu_time_start_;
};

#endif // UTIL_HPP
