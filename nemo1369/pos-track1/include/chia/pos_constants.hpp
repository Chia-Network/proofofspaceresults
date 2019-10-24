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

#ifndef SRC_CPP_POS_CONSTANTS_HPP_
#define SRC_CPP_POS_CONSTANTS_HPP_

#include <numeric>

// Unique plot id which will be used as an AES key, and determines the PoSpace.
const uint32_t kIdLen = 32;

// Must be set high enough to prevent attacks of fast plotting
const uint32_t kMinPlotSize = 15;

// Set at 59 to allow easy use of 64 bit integers
const uint32_t kMaxPlotSize = 59;

// How many f7s per C1 entry, and how many C1 entries per C2 entry
const uint32_t kCheckpoint1Interval = 10000;
const uint32_t kCheckpoint2Interval = 10000;

// F1 evaluations are done in batches of 2^kBatchSizes
const uint32_t kBatchSizes = 8;

// EPP for the final file, the higher this is, the less variability, and lower delta
// Note: if this is increased, park_vector size must increase
const uint32_t kEntriesPerPark = 2048;

// To store deltas for EPP entries, the average delta must be less than this number of bits
const double kMaxAverageDeltaTable1 = 5.6;
const double kMaxAverageDelta = 3.5;

// C3 entries contain deltas for f7 values, the max average size is the following
const double kC3BitsPerEntry = 2.4;

// The number of bits in the stub is k minus this value
const uint8_t kStubMinusBits = 3;

// The ANS encoding R values for the 7 final plot tables
// Tweaking the R values might allow lowering of the max average deltas, and reducing final
// plot size
const double kRValues[7] = {4.7, 2.75, 2.75, 2.7, 2.6, 2.45};

// The ANS encoding R value for the C3 checkpoint table
const double kC3R = 1.0;

// Plot format (no compatibility guarantees with other formats). If any of the
// above contants are changed, or file format is changed, the version should
// be incremented.
const std::string kFormatDescription = "alpha-v0.4";

struct plot_entry {
    uint64_t y;
    uint64_t pos;
    uint64_t offset;
    uint128_t left_metadata;     // We only use left_metadata, unless metadata does not
    uint128_t right_metadata;    // fit in 128 bits.
};

struct zerg_bits {
    uint128_t value;
    uint128_t len;

    zerg_bits() : value(0), len(0) {};

    zerg_bits(uint128_t new_value, uint128_t new_len) : value(new_value), len(new_len) {};

    zerg_bits slice(uint128_t begin) const {
        return slice(begin, len);
    }

    zerg_bits slice(uint128_t begin, uint128_t end) const {
        uint128_t new_len = end - begin;
        uint128_t new_value = value >> (len - end);
        if (new_len < 128) {
            new_value &= (((uint128_t)1 << (new_len)) - 1);
        } else {
            throw std::invalid_argument("Watch here bits");
        }
        return {new_value, new_len};
    }

    zerg_bits operator+(const zerg_bits &b) const {
        return {(value << b.len) + b.value, len + b.len};
    }

    zerg_bits operator^(const zerg_bits &other) const {
        return {value ^ (other.value), len};
    }

    void to_bytes(uint8_t *buffer) const {
        uint8_t shift = utilities::byte_align(len) - len;
        uint128_t val = value << shift;
        uint32_t cnt = 0;

        uint8_t iterations = len / 8;
        if (len % 8)
            iterations++;
        for (uint8_t i = 0; i < iterations; i++) {
            buffer[iterations - i - 1] = (val & 0xff);
            val >>= 8;
        }
    }
};

#endif    // SRC_CPP_POS_CONSTANTS_HPP_
