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

#ifndef POS_CONSTANTS_HPP_
#define POS_CONSTANTS_HPP_

#include <cstdint>
#include <numeric>
#include <string>

// Unique plot id which will be used as an AES key, and determines the PoSpace.
constexpr uint32_t kIdLen = 32;

// Must be set high enough to prevent attacks of fast plotting
constexpr uint32_t kMinPlotSize = 15;

// Set at 59 to allow easy use of 64 bit integers
constexpr uint32_t kMaxPlotSize = 59;

// How many f7s per C1 entry, and how many C1 entries per C2 entry
constexpr uint32_t kCheckpoint1Interval = 10000;
constexpr uint32_t kCheckpoint2Interval = 10000;

// F1 evaluations are done in batches of 2^kBatchSizes
constexpr uint32_t kBatchSizes = 8;

// EPP for the final file, the higher this is, the less variability, and lower
// delta Note: if this is increased, ParkVector size must increase
constexpr uint32_t kEntriesPerPark = 2048;

// To store deltas for EPP entries, the average delta must be less than this
// number of bits
constexpr double kMaxAverageDeltaTable1 = 5.6;
constexpr double kMaxAverageDelta = 3.5;

// C3 entries contain deltas for f7 values, the max average size is the
// following
constexpr double kC3BitsPerEntry = 2.4;

// The number of bits in the stub is k minus this value
constexpr uint8_t kStubMinusBits = 3;

// The ANS encoding R values for the 7 final plot tables
// Tweaking the R values might allow lowering of the max average deltas, and
// reducing final plot size
constexpr double kRValues[7] = {4.7, 2.75, 2.75, 2.7, 2.6, 2.45};

// The ANS encoding R value for the C3 checkpoint table
constexpr double kC3R = 1.0;

// Plot format (no compatibility guarantees with other formats). If any of the
// above contants are changed, or file format is changed, the version should
// be incremented.
inline static const std::string kFormatDescription = "alpha-v0.4";
constexpr int kFormatDescriptionLength = 10;

constexpr std::size_t operator""_KB(unsigned long long v) { return 1024u * v; }

constexpr std::size_t operator""_MB(unsigned long long v) {
  return 1_KB * 1_KB * v;
}

constexpr std::size_t operator""_GB(unsigned long long v) {
  return 1_MB * 1_KB * v;
}

constexpr std::size_t operator""_TB(unsigned long long v) {
  return 1_GB * 1_KB * v;
}

struct PlotEntry {
  uint64_t y;
  uint64_t pos;
  uint64_t offset;

  // We only use left_metadata, unless metadata does not fit in 128 bits
  __uint128_t left_metadata;
  __uint128_t right_metadata;
};

#if 0
// disable warning
#define DO_PRAGMA(X) _Pragma(#X)
#define DISABLE_WARNING(warningName)                                           \
  DO_PRAGMA(GCC diagnostic ignored #warningName)
#endif

#endif // SRC_CPP_POS_CONSTANTS_HPP_
