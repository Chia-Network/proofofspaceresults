//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
// Copyright (c) 2018 Chia Network Inc
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//
// Distributed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#ifndef SRC_CPP_CALCULATE_BUCKET_HPP_
#define SRC_CPP_CALCULATE_BUCKET_HPP_

#include <stdint.h>
#include <cmath>
#include <vector>
#include <bitset>
#include <iostream>
#include <map>
#include <algorithm>
#include <utility>

#include "utilities.hpp"
#include "bits.hpp"
#include "aes.hpp"
#include "pos_constants.hpp"

// AES block size
const uint8_t kBlockSizeBits = 128;

// Extra bits of output from the f functions. Instead of being a function from k -> k bits,
// it's a function from k -> k + kExtraBits bits. This allows less collisions in matches.
// Refer to the paper for mathematical motivations.
const uint8_t kExtraBits = 5;

// Convenience variable
const uint8_t kExtraBitsPow = 1 << kExtraBits;

// B and C groups which constitute a bucket, or BC group. These groups determine how
// elements match with each other. Two elements must be in adjacent buckets to match.
const uint16_t kB = 60;
const uint16_t kC = 509;
const uint16_t kBC = kB * kC;

// This (times k) is the length of the metadata that must be kept for each entry. For example,
// for a tbale 4 entry, we must keep 4k additional bits for each entry, which is used to
// compute f5.
std::map<uint8_t, uint8_t> kVectorLens = {{2, 1}, {3, 2}, {4, 4}, {5, 4}, {6, 3}, {7, 2}, {8, 0}};

// Precomputed shifts that specify which entries match with which other entries
// in adjacent buckets.
uint16_t matching_shifts_c[2][kC];

// Performs the precomputation of shifts.
void precompute_shifts() {
    for (uint8_t parity = 0; parity < 2; parity++) {
        for (uint16_t r = 0; r < kExtraBitsPow; r++) {
            uint16_t v = (uint16_t)pow((2 * r + parity), 2) % kC;
            matching_shifts_c[parity][r] = v;
        }
    }
}

// Class to evaluate F1
class f1_calculator {
public:
    inline f1_calculator(uint8_t k, uint8_t *aes_key) {
        this->k_ = k;
        this->aes_key_ = new uint8_t[32];

        // First byte is 1, the index of this table
        this->aes_key_[0] = 1;
        memcpy(this->aes_key_ + 1, aes_key, 31);

        // Loads the key into the global AES context
        aes_load_key(this->aes_key_, 32);

        // Precomputes the shifts, this is only done once
        precompute_shifts();
    }

    inline ~f1_calculator() {
        delete[] this->aes_key_;
    }

    // Disable copying
    f1_calculator(const f1_calculator &) = delete;

    // Reloads the AES key. If another F1 or Fx object is created, this must be called
    // since the AES context is global.
    inline void reload_key() {
        aes_load_key(this->aes_key_, 32);
    }

    // Performs one evaluation of the F function on input L of k bits.
    inline bits calculate_f(const bits &L) const {
        uint8_t num_output_bits = k_;

        // Calculates the counter that will be AES-encrypted. since k < 128, we can fit several k bit
        // blocks into one AES block.
        bits counter((L.get_value() * (uint128_t)num_output_bits) / kBlockSizeBits, kBlockSizeBits);

        // How many bits are before L, in the current block
        uint32_t bits_before_L = (L.get_value() * (uint128_t)num_output_bits) % kBlockSizeBits;

        // How many bits of L are in the current block (the rest are in the next block)
        const uint8_t bits_of_L = std::min((uint8_t)(kBlockSizeBits - bits_before_L), num_output_bits);

        // True if L is divided into two blocks, and therefore 2 AES encryptions will be performed.
        const bool spans_two_blocks = bits_of_L < num_output_bits;

        uint8_t counter_bytes[kBlockSizeBits / 8];
        uint8_t ciphertext_bytes[kBlockSizeBits / 8];
        bits output_bits;

        // This counter is what will be encrypted. This is similar to AES counter mode, but not XORing
        // any data at the end.
        counter.to_bytes(counter_bytes);
        aes256_enc(counter_bytes, ciphertext_bytes);
        bits ciphertext0(ciphertext_bytes, kBlockSizeBits / 8, kBlockSizeBits);

        if (spans_two_blocks) {
            // Performs another encryption if necessary
            ++counter;
            counter.to_bytes(counter_bytes);
            aes256_enc(counter_bytes, ciphertext_bytes);
            bits ciphertext1(ciphertext_bytes, kBlockSizeBits / 8, kBlockSizeBits);
            output_bits = ciphertext0.slice(bits_before_L) + ciphertext1.slice(0, num_output_bits - bits_of_L);
        } else {
            output_bits = ciphertext0.slice(bits_before_L, bits_before_L + num_output_bits);
        }

        // Adds the first few bits of L to the end of the output, production k + kExtraBits of output
        bits extra_data = L.slice(0, kExtraBits);
        if (extra_data.size() < kExtraBits) {
            extra_data += bits(0, kExtraBits - extra_data.size());
        }
        return output_bits + extra_data;
    }

    // Returns an evaluation of F1(L), and the metadata (L) that must be stored to evaluate F2.
    inline std::pair<bits, bits> calculate_bucket(const bits &L) {
        return std::make_pair(calculate_f(L), L);
    }

    // Returns an evaluation of F1(L), and the metadata (L) that must be stored to evaluate F2,
    // for 'number_of_evaluations' adjacent inputs.
    inline std::vector<std::pair<bits, bits>> calculate_buckets(const bits &start_L, uint64_t number_of_evaluations) {
        uint8_t num_output_bits = k_;

        uint64_t two_to_the_k = (uint64_t)1 << k_;
        if (start_L.get_value() + number_of_evaluations > two_to_the_k) {
            throw "Evaluation out of range";
        }
        // Counter for the first input
        uint64_t counter = (start_L.get_value() * (uint128_t)num_output_bits) / kBlockSizeBits;
        // Counter for the last input
        uint64_t counter_end =
            ((start_L.get_value() + (uint128_t)number_of_evaluations + 1) * num_output_bits) / kBlockSizeBits;

        std::vector<bits> blocks;
        uint64_t L = (counter * kBlockSizeBits) / num_output_bits;
        uint8_t counter_bytes[kBlockSizeBits / 8];
        uint8_t ciphertext_bytes[kBlockSizeBits / 8];

        // Evaluates the AES for each block
        while (counter <= counter_end) {
            bits counter_bits(counter, kBlockSizeBits);
            counter_bits.to_bytes(counter_bytes);
            aes256_enc(counter_bytes, ciphertext_bytes);
            bits ciphertext(ciphertext_bytes, kBlockSizeBits / 8, kBlockSizeBits);
            blocks.push_back(std::move(ciphertext));
            ++counter;
        }

        std::vector<std::pair<bits, bits>> results;
        uint64_t block_number = 0;
        uint8_t start_bit = (start_L.get_value() * (uint128_t)num_output_bits) % kBlockSizeBits;

        // For each of the inputs, grabs the correct slice from the encrypted data.
        for (L = start_L.get_value(); L < start_L.get_value() + number_of_evaluations; L++) {
            bits L_bits = bits(L, k_);

            // Takes the first kExtraBits bits from the input, and adds zeroes if it's not enough
            bits extra_data = L_bits.slice(0, kExtraBits);
            if (extra_data.size() < kExtraBits) {
                extra_data = extra_data + bits(0, kExtraBits - extra_data.size());
            }

            if (start_bit + num_output_bits < kBlockSizeBits) {
                // Everything can be sliced from the current block
                results.emplace_back(blocks[block_number].slice(start_bit, start_bit + num_output_bits) + extra_data,
                                     L_bits);
            } else {
                // Must move forward one block
                bits left = blocks[block_number].slice(start_bit);
                bits right = blocks[block_number + 1].slice(0, num_output_bits - (kBlockSizeBits - start_bit));
                results.emplace_back(left + right + extra_data, L_bits);
                ++block_number;
            }
            // Start bit of the output slice in the current block
            start_bit = (start_bit + num_output_bits) % kBlockSizeBits;
        }
        return results;
    }

private:
    // Size of the plot
    uint8_t k_;

    // 32 byte AES key
    uint8_t *aes_key_;
};

// Class to evaluate F2 .. F7.
class fx_calculator {
public:
    inline fx_calculator(uint8_t k, uint8_t table_index, uint8_t *aes_key) {
        this->k_ = k;
        this->aes_key_ = new uint8_t[32];
        this->table_index_ = table_index;
        this->length_ = kVectorLens[table_index] * k;

        // First byte is the index of the table
        this->aes_key_[0] = table_index;
        memcpy(this->aes_key_ + 1, aes_key, 15);

        // Loads the AES key into the global AES context. It is 16 bytes since AES128 is used
        // for these f functions (as opposed to f1, which uses a 32 byte key). Note that, however,
        // block sizes are still 128 bits (32 bytes).
        aes_load_key(this->aes_key_, 16);

        // One time precomputation of the shifts
        precompute_shifts();

        // Preallocates vector to be used for matching
        for (uint16_t i = 0; i < kC; i++) {
            std::vector<uint16_t> new_vec;
            this->R_positions.push_back(new_vec);
            this->R_bids.push_back(new_vec);
        }
    }

    inline ~fx_calculator() {
        delete[] this->aes_key_;
    }

    // Disable copying
    fx_calculator(const fx_calculator &) = delete;

    inline void reload_key() {
        aes_load_key(this->aes_key_, 16);
    }

    // Performs one evaluation of the f function, whose input is divided into 3 pieces of at
    // most 128 bits each.
    inline bits calculate_f(const bits &La, const bits &Lb, const bits &Ra, const bits &Rb) {
        assert(La.size() + Lb.size() == Ra.size() + Rb.size() && La.size() + Lb.size() == length_);

        std::memset(this->block_1, 0, kBlockSizeBits / 8);
        std::memset(this->block_2, 0, kBlockSizeBits / 8);
        std::memset(this->block_3, 0, kBlockSizeBits / 8);
        std::memset(this->block_4, 0, kBlockSizeBits / 8);

        if (length_ * 2 <= kBlockSizeBits) {
            (La + Ra).to_bytes(block_1);
            aes128_enc(this->block_1, this->ciphertext);
        } else if (length_ * 2 <= 2 * kBlockSizeBits) {
            La.to_bytes(this->block_1);
            Ra.to_bytes(this->block_2);
            aes128_2b(this->block_1, this->block_2, this->ciphertext);
        } else if (length_ * 2 <= 3 * kBlockSizeBits) {
            La.to_bytes(this->block_1);
            Ra.to_bytes(this->block_2);
            (Lb + Rb).to_bytes(this->block_3);
            aes128_3b(this->block_1, this->block_2, this->block_3, this->ciphertext);
        } else {
            assert(length_ * 2 <= 4 * kBlockSizeBits);
            La.to_bytes(this->block_1);
            Lb.to_bytes(this->block_2);
            Ra.to_bytes(this->block_3);
            Rb.to_bytes(this->block_4);
            aes128_4b(this->block_1, this->block_2, this->block_3, this->block_4, this->ciphertext);
        }

        return bits(ciphertext, kBlockSizeBits / 8, kBlockSizeBits).slice(0, k_ + kExtraBits);
    }

    // Composes two metadatas L and R, into a metadata for the next table.
    inline bits compose(const bits &L, const bits &R) {
        switch (table_index_) {
            case 2:
            case 3:
                return L + R;
            case 4:
                return L ^ R;
            case 5:
                assert(length_ % 4 == 0);
                return (L ^ R).slice(0, length_ * 3 / 4);
            case 6:
                assert(length_ % 3 == 0);
                return (L ^ R).slice(0, length_ * 2 / 3);
            default:
                return bits();
        }
    }

    // Returns an evaluation of F_i(L), and the metadata (L) that must be stored to evaluate F_i+1.
    inline std::pair<bits, bits> calculate_bucket(const bits &y1, const bits &y2, const bits &L, const bits &R,
                                                  bool check = false) {
        // y1 is xored into the result. This ensures that we have some cryptographic "randomness"
        // encoded into each f function, since f1 output y is the results of an AES256 encryption.
        // All other f functions apart from f1 don't use AES256, they use 2 round AES128.
        if (check) {
            std::vector<plot_entry> l_entry, r_entry;
            l_entry = r_entry = {plot_entry()};
            l_entry[0].y = y1.get_value();
            r_entry[0].y = y2.get_value();
            if (find_matches(l_entry, r_entry).empty())
                return std::make_pair(bits(), bits());
        }
        if (L.size() <= kBlockSizeBits) {
            return std::make_pair(calculate_f(L, bits(), R, bits()) ^ y1, compose(L, R));
        } else {
            return std::make_pair(calculate_f(L.slice(0, kBlockSizeBits),
                                              L.slice(kBlockSizeBits),
                                              R.slice(0, kBlockSizeBits),
                                              R.slice(kBlockSizeBits)) ^
                                      y1,
                                  compose(L, R));
        }
    }

    // Given two buckets with entries (y values), computes which y values match, and returns a list
    // of the pairs of indeces into bucket_L and bucket_R.
    inline std::vector<std::pair<uint16_t, uint16_t>> find_matches(const std::vector<plot_entry> &bucket_L,
                                                                   const std::vector<plot_entry> &bucket_R) {
        std::vector<std::pair<uint16_t, uint16_t>> matches;
        for (uint16_t i = 0; i < kC; i++) {
            this->R_bids[i].clear();
            this->R_positions[i].clear();
        }
        uint16_t parity = (bucket_L[0].y / kBC) % 2;

        for (uint16_t pos_R = 0; pos_R < bucket_R.size(); pos_R++) {
            R_bids[bucket_R[pos_R].y % kC].push_back((bucket_R[pos_R].y % kBC) / kC);
            R_positions[bucket_R[pos_R].y % kC].push_back(pos_R);
        }

        for (uint16_t pos_L = 0; pos_L < bucket_L.size(); pos_L++) {
            uint16_t yl_bid = (bucket_L[pos_L].y % kBC) / kC;
            uint16_t yl_cid = bucket_L[pos_L].y % kC;
            for (uint8_t m = 0; m < kExtraBitsPow; m++) {
                uint16_t target_bid = (yl_bid + m);
                uint16_t target_cid = yl_cid + matching_shifts_c[parity][m];
                if (target_bid >= kB) {
                    target_bid -= kB;
                }
                if (target_cid >= kC) {
                    target_cid -= kC;
                }

                for (uint32_t i = 0; i < R_bids[target_cid].size(); i++) {
                    uint16_t R_bid = R_bids[target_cid][i];
                    if (target_bid == R_bid) {
                        // uint64_t yl_bucket = bucket_L[pos_L].y / kBC;
                        // assert(yl_bucket == bucket_R[R_positions[target_cid][i]].y / kBC));
                        matches.push_back(std::make_pair(pos_L, R_positions[target_cid][i]));
                    }
                }
            }
        }
        return matches;
    }

private:
    uint8_t k_;
    uint8_t *aes_key_;
    uint8_t table_index_;
    uint8_t length_;
    uint8_t block_1[kBlockSizeBits / 8];
    uint8_t block_2[kBlockSizeBits / 8];
    uint8_t block_3[kBlockSizeBits / 8];
    uint8_t block_4[kBlockSizeBits / 8];
    uint8_t ciphertext[kBlockSizeBits / 8];
    std::vector<std::vector<uint16_t>> R_positions;
    std::vector<std::vector<uint16_t>> R_bids;
};

#endif    // SRC_CPP_CALCULATE_BUCKET_HPP_
