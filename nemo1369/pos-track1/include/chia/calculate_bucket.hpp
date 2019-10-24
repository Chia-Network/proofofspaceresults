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

#ifndef SRC_CPP_CALCULATE_BUCKET_HPP_
#define SRC_CPP_CALCULATE_BUCKET_HPP_

#include <cstdint>
#include <cmath>
#include <vector>
#include <bitset>
#include <iostream>
#include <map>
#include <algorithm>
#include <utility>

#include <chia/utilities.hpp>
#include <chia/bits.hpp>
#include <chia/aes.hpp>
#include <chia/pos_constants.hpp>

// AES block size
const uint8_t kBlockSizeBits = 128;
const uint8_t kBlockSizeBytes = 128 / 8;

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

// TODO: надо посчитать какой размер
const uint64_t kBucketMaxSize = 2UL << 10U;


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
        this->two_to_the_k_ = 1 << k;
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

        uint8_t counter_bytes[kBlockSizeBytes];
        uint8_t ciphertext_bytes[kBlockSizeBytes];
        bits output_bits;

        // This counter is what will be encrypted. This is similar to AES counter mode, but not XORing
        // any data at the end.
        counter.to_bytes(counter_bytes);
        aes256_enc(counter_bytes, ciphertext_bytes);
        bits ciphertext0(ciphertext_bytes, kBlockSizeBytes, kBlockSizeBits);

        if (spans_two_blocks) {
            // Performs another encryption if necessary
            ++counter;
            counter.to_bytes(counter_bytes);
            aes256_enc(counter_bytes, ciphertext_bytes);
            bits ciphertext1(ciphertext_bytes, kBlockSizeBytes, kBlockSizeBits);
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
    inline std::vector<uint128_t> calculate_buckets(const uint128_t &start_L_value, uint64_t number_of_evaluations) {
        uint8_t num_output_bits = k_;

//        if (start_L_value + number_of_evaluations > two_to_the_k_) {
//            throw "Evaluation out of range";
//        }

        // Counter for the first input
        uint64_t counter = (start_L_value * (uint128_t)k_) / kBlockSizeBits;
        // Counter for the last input
        uint64_t counter_end = ((start_L_value + (uint128_t)number_of_evaluations + 1) * k_) / kBlockSizeBits;
        uint64_t counter_length = counter_end - counter + 1;

        //uint64_t L = start_L_value; //uint64_t L = (counter * kBlockSizeBits) / k_;
        uint8_t counter_bytes[kBlockSizeBits / 8];
        uint8_t ciphertext_bytes[kBlockSizeBits / 8];

        std::vector<uint128_t> blocks(counter_length);

        // Evaluates the AES for each block
        for (uint64_t i = 0; i < counter_length; ++i) {
            uint128_t ciphert_result = 0;
            bits counter_bits(counter + i, kBlockSizeBits);
            counter_bits.to_bytes(counter_bytes);
            aes256_enc(counter_bytes, ciphertext_bytes);
            for (size_t j = 0; j < 16; ++j) {
                ciphert_result = ciphert_result << 8;
                ciphert_result += ciphertext_bytes[j];
            }

            blocks[i] = ciphert_result;

        }

        std::vector<uint128_t > results(number_of_evaluations);

        uint64_t block_number = 0;
        uint8_t start_bit = (start_L_value * (uint128_t)num_output_bits) % kBlockSizeBits;
        // For each of the inputs, grabs the correct slice from the encrypted data.
        for (uint64_t L = 0; L < number_of_evaluations; L++) {

            // Takes the first kExtraBits bits from the input, and adds zeroes if it's not enough
            uint64_t extra_data = (L + start_L_value) >> (k_ - kExtraBits);
            uint128_t k_mask = ((uint128_t)1 << (num_output_bits)) - 1;

            if (start_bit + num_output_bits < kBlockSizeBits) {
                // Everything can be sliced from the current block
                results[L] = (((blocks[block_number] >> (128 - start_bit - num_output_bits)) & k_mask) << kExtraBits) +
                    extra_data;
            } else {
                // Must move forward one block
                uint8_t left_size = kBlockSizeBits - start_bit;
                uint8_t right_size = num_output_bits - left_size;

                uint128_t left_mask = ((uint128_t)1 << left_size) - 1;
                uint128_t left = blocks[block_number] & left_mask;

                uint128_t right = 0;
                if (right_size != 0)
                    right = (uint128_t)blocks[block_number + 1] >> (128 - right_size);
                results[L] = (((left << right_size) + right) << kExtraBits) + extra_data;
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
    uint64_t two_to_the_k_;
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
    // TODO
    inline zerg_bits zerg_calculate_f(const zerg_bits &La, const zerg_bits &Lb, const zerg_bits &Ra, const zerg_bits &Rb) {

        if (length_ * 2 <= kBlockSizeBits) {
            memset(this->block_1, 0, kBlockSizeBytes);
            (La + Ra).to_bytes(block_1);
            aes128_enc(this->block_1, this->ciphertext);
        } else if (length_ * 2 <= 2 * kBlockSizeBits) {
            memset(this->block_1, 0, kBlockSizeBytes);
            memset(this->block_2, 0, kBlockSizeBytes);
            La.to_bytes(this->block_1);
            Ra.to_bytes(this->block_2);
            aes128_2b(this->block_1, this->block_2, this->ciphertext);
        } else if (length_ * 2 <= 3 * kBlockSizeBits) {
            memset(this->block_1, 0, kBlockSizeBytes);
            memset(this->block_2, 0, kBlockSizeBytes);
            memset(this->block_3, 0, kBlockSizeBytes);
            La.to_bytes(this->block_1);
            Ra.to_bytes(this->block_2);
            (Lb + Rb).to_bytes(this->block_3);
            aes128_3b(this->block_1, this->block_2, this->block_3, this->ciphertext);
        } else {
            assert(length_ * 2 <= 4 * kBlockSizeBits);
            memset(this->block_1, 0, kBlockSizeBytes);
            memset(this->block_2, 0, kBlockSizeBytes);
            memset(this->block_3, 0, kBlockSizeBytes);
            memset(this->block_4, 0, kBlockSizeBytes);
            La.to_bytes(this->block_1);
            Lb.to_bytes(this->block_2);
            Ra.to_bytes(this->block_3);
            Rb.to_bytes(this->block_4);
            aes128_4b(this->block_1, this->block_2, this->block_3, this->block_4, this->ciphertext);
        }

        uint128_t tmp = 0;
        for (unsigned char j : ciphertext) {
            tmp = tmp << 8U;
            tmp += j;
        }
        return zerg_bits(tmp, kBlockSizeBits).slice(0, k_ + kExtraBits);
    }

    // Composes two metadatas L and R, into a metadata for the next table.
    inline zerg_bits zerg_compose(const zerg_bits &L, const zerg_bits &R) {
        switch (table_index_) {
            case 2:
            case 3:
                return L + R;
            case 4:
                return L ^ R;
            case 5:
                return (L ^ R).slice(0, length_ * 3 / 4);
            case 6:
                return (L ^ R).slice(0, length_ * 2 / 3);
            default:
                return zerg_bits();
        }
    }

    // Returns an evaluation of F_i(L), and the metadata (L) that must be stored to evaluate F_i+1.
    inline std::pair<zerg_bits, zerg_bits> zerg_calculate_bucket128(const zerg_bits &y1, const zerg_bits &L, const zerg_bits &R) {
        // y1 is xored into the result. This ensures that we have some cryptographic "randomness"
        // encoded into each f function, since f1 output y is the results of an AES256 encryption.
        // All other f functions apart from f1 don't use AES256, they use 2 round AES128.
        return std::make_pair(zerg_calculate_f(L, zerg_bits(), R, zerg_bits()) ^ y1, zerg_compose(L, R));
    }

    // Returns an evaluation of F_i(L), and the metadata (L) that must be stored to evaluate F_i+1.
    inline std::pair<zerg_bits, zerg_bits> zerg_calculate_bucket256(const zerg_bits &y1, const zerg_bits &L, const zerg_bits &R) {
        // y1 is xored into the result. This ensures that we have some cryptographic "randomness"
        // encoded into each f function, since f1 output y is the results of an AES256 encryption.
        // All other f functions apart from f1 don't use AES256, they use 2 round AES128.
        return std::make_pair(zerg_calculate_f(L.slice(0, kBlockSizeBits), L.slice(kBlockSizeBits), R.slice(0, kBlockSizeBits),
                                                   R.slice(kBlockSizeBits)) ^ y1, zerg_compose(L, R));
    }

    // Given two buckets with entries (y values), computes which y values match, and returns a list
    // of the pairs of indeces into bucket_L and bucket_R. Indeces l and r match iff:
    //   let  yl = bucket_L[l].y,  yr = bucket_R[r].y
    //
    //   For any 0 <= m < kExtraBitsPow:
    //   yl / kBC + 1 = yR / kBC   AND
    //   (yr % kBC) / kC - (yl % kBC) / kC = m   (mod kB)  AND
    //   (yr % kBC) % kC - (yl % kBC) % kC = (2m + (yl/kBC) % 2)^2   (mod kC)
    //
    // Instead of doing the naive algorithm, which is an O(kExtraBitsPow * N^2) comparisons on bucket
    // length, we can store all the R values and lookup each of our 32 candidates to see if any R
    // value matches.
    // This function can be further optimized by removing the inner loop, and being more careful
    // with memory allocation.
    inline std::vector<std::pair<uint16_t, uint16_t>> find_matches(const plot_entry *bucket_L, const uint64_t size_bucket_L,
                                                                   const plot_entry *bucket_R, const uint64_t size_bucket_R) {
        std::vector<std::pair<uint16_t, uint16_t>> matches;
        for (uint16_t i = 0; i < kC; i++) {
            this->R_bids[i].clear();
            this->R_positions[i].clear();
        }
        uint16_t parity = (bucket_L[0].y / kBC) % 2;

        for (std::size_t pos_R = 0; pos_R < size_bucket_R; pos_R++) {
            uint64_t index = bucket_R[pos_R].y % kC;
            R_bids[index].push_back((bucket_R[pos_R].y % kBC) / kC);
            R_positions[index].push_back(pos_R);
        }

        for (std::size_t pos_L = 0; pos_L < size_bucket_L; pos_L++) {
            uint16_t yl_bid = (bucket_L[pos_L].y % kBC) / kC;
            uint16_t yl_cid = bucket_L[pos_L].y % kC;
            for (uint8_t m = 0; m < kExtraBitsPow; m++) {
                uint16_t target_bid = (yl_bid + m);
                uint16_t target_cid = yl_cid + matching_shifts_c[parity][m];

                // This is faster than %
                if (target_bid >= kB) {
                    target_bid -= kB;
                }
                if (target_cid >= kC) {
                    target_cid -= kC;
                }

                for (std::size_t i = 0; i < R_bids[target_cid].size(); i++) {
                    uint16_t R_bid = R_bids[target_cid][i];
                    if (target_bid == R_bid) {
                        uint64_t yl_bucket = bucket_L[pos_L].y / kBC;
                        if (yl_bucket + 1 == bucket_R[R_positions[target_cid][i]].y / kBC) {
                            matches.emplace_back(pos_L, R_positions[target_cid][i]);
                        }
                    }
                }
            }
        }
        return matches;
    }

    inline std::vector<std::pair<uint16_t, uint16_t>> find_matches(const std::vector<plot_entry> &bucket_L,
                                                                   const std::vector<plot_entry> &bucket_R) {
        std::vector<std::pair<uint16_t, uint16_t>> matches;
        for (uint16_t i = 0; i < kC; i++) {
            this->R_bids[i].clear();
            this->R_positions[i].clear();
        }
        uint16_t parity = (bucket_L[0].y / kBC) % 2;

        for (std::size_t pos_R = 0; pos_R < bucket_R.size(); pos_R++) {
            R_bids[bucket_R[pos_R].y % kC].push_back((bucket_R[pos_R].y % kBC) / kC);
            R_positions[bucket_R[pos_R].y % kC].push_back(pos_R);
        }

        for (std::size_t pos_L = 0; pos_L < bucket_L.size(); pos_L++) {
            uint16_t yl_bid = (bucket_L[pos_L].y % kBC) / kC;
            uint16_t yl_cid = bucket_L[pos_L].y % kC;
            for (uint8_t m = 0; m < kExtraBitsPow; m++) {
                uint16_t target_bid = (yl_bid + m);
                uint16_t target_cid = yl_cid + matching_shifts_c[parity][m];

                // This is faster than %
                if (target_bid >= kB) {
                    target_bid -= kB;
                }
                if (target_cid >= kC) {
                    target_cid -= kC;
                }

                for (std::size_t i = 0; i < R_bids[target_cid].size(); i++) {
                    uint16_t R_bid = R_bids[target_cid][i];
                    if (target_bid == R_bid) {
                        uint64_t yl_bucket = bucket_L[pos_L].y / kBC;
                        if (yl_bucket + 1 == bucket_R[R_positions[target_cid][i]].y / kBC) {
                            matches.emplace_back(pos_L, R_positions[target_cid][i]);
                        }
                    }
                }
            }
        }
        return matches;
    }

    //Тут то что было и нужно для прувера (не переделывал пока)
    // Performs one evaluation of the f function, whose input is divided into 3 pieces of at
    // most 128 bits each.
    inline bits calculate_f(const bits &La, const bits &Lb, const bits &Ra, const bits &Rb) {
        assert(La.size() + Lb.size() == Ra.size() + Rb.size() && La.size() + Lb.size() == length_);

        memset(this->block_1, 0, kBlockSizeBytes);
        memset(this->block_2, 0, kBlockSizeBytes);
        memset(this->block_3, 0, kBlockSizeBytes);
        memset(this->block_4, 0, kBlockSizeBytes);

        if (length_ * 2 <= kBlockSizeBits) {
            (La + Ra).to_bytes(block_1);
            auto t = La + Ra;
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

        return bits(ciphertext, kBlockSizeBytes, kBlockSizeBits).slice(0, k_ + kExtraBits);
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
    inline std::pair<bits, bits> calculate_bucket(const bits &y1, const bits &L, const bits &R) {
        // y1 is xored into the result. This ensures that we have some cryptographic "randomness"
        // encoded into each f function, since f1 output y is the results of an AES256 encryption.
        // All other f functions apart from f1 don't use AES256, they use 2 round AES128.
        if (L.size() <= kBlockSizeBits) {
            auto tr = bits();
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
private:
    uint8_t k_;
    uint8_t *aes_key_;
    uint8_t table_index_;
    uint8_t length_;
    uint8_t block_1[kBlockSizeBytes];
    uint8_t block_2[kBlockSizeBytes];
    uint8_t block_3[kBlockSizeBytes];
    uint8_t block_4[kBlockSizeBytes];
    uint8_t ciphertext[kBlockSizeBytes];
    std::vector<uint16_t> R_positions[kC];
    std::vector<uint16_t> R_bids[kC];
};

#endif    // SRC_CPP_CALCULATE_BUCKET_HPP_
