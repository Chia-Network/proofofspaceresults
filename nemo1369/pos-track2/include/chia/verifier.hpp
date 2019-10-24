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

#ifndef SRC_CPP_VERIFIER_HPP_
#define SRC_CPP_VERIFIER_HPP_

#include <vector>
#include <utility>
#include "calculate_bucket.hpp"

class verifier {
public:
    // Gets the quality string from a proof in proof ordering. The quality string is two
    // adjacent values, determined by the quality index (1-32), and the proof in plot
    // ordering.
    large_bits get_quality_string(uint8_t k, large_bits proof, uint16_t quality_index) {
        // Converts the proof from proof ordering to plot ordering
        for (uint8_t table_index = 1; table_index < 7; table_index++) {
            large_bits new_proof;
            uint16_t size = k * (1 << (table_index - 1));
            for (uint8_t j = 0; j < (1 << (7 - table_index)); j += 2) {
                large_bits L = proof.slice(j * size, (j + 1) * size);
                large_bits R = proof.slice((j + 1) * size, (j + 2) * size);
                if (compare_proof_bits(L, R, k)) {
                    new_proof += (L + R);
                } else {
                    new_proof += (R + L);
                }
            }
            proof = new_proof;
        }
        // Returns two of the x values, based on the quality index
        return proof.slice(k * quality_index, k * (quality_index + 2));
    }

    // Validates a proof of space, and returns the quality string if the proof is valid for the given
    // k and challenge. If the proof is invalid, it returns an empty large_bits().
    large_bits validate_proof(uint8_t *id, uint8_t k, uint8_t *challenge, uint8_t *proof_bytes, uint16_t proof_size) {
        large_bits proof_bits = large_bits(proof_bytes, proof_size, proof_size * 8);
        if (k * 64 != proof_bits.size()) {
            return large_bits();
        }
        std::vector<bits> proof;
        std::vector<bits> ys;
        std::vector<bits> metadata;
        f1_calculator f1(k, id);

        // Calculates f1 for each of the given xs. Note that the proof is in proof order.
        for (uint8_t i = 0; i < 64; i++) {
            proof.emplace_back(proof_bits.slice_bits_to_int(k * i, k * (i + 1)), k);
            std::pair<bits, bits> results = f1.calculate_bucket(proof[i]);
            ys.push_back(std::get<0>(results));
            metadata.push_back(std::get<1>(results));
        }

        // Calculates fx for each table from 2..7, making sure everything matches on the way.
        for (uint8_t depth = 2; depth < 8; depth++) {
            fx_calculator f(k, depth, id);
            std::vector<bits> new_ys;
            std::vector<bits> new_metadata;
            for (uint8_t i = 0; i < (1 << (8 - depth)); i += 2) {
                plot_entry l_plot_entry {};
                plot_entry r_plot_entry {};
                l_plot_entry.y = ys[i].get_value();
                r_plot_entry.y = ys[i + 1].get_value();
                std::vector<plot_entry> bucket_L = {l_plot_entry};
                std::vector<plot_entry> bucket_R = {r_plot_entry};

                // If there is no match, fails.
                if (f.find_matches(bucket_L, bucket_R).size() != 1) {
                    return large_bits();
                }
                std::pair<bits, bits> results = f.calculate_bucket(ys[i], ys[i + 1], metadata[i], metadata[i + 1]);
                new_ys.push_back(std::get<0>(results));
                new_metadata.push_back(std::get<1>(results));
            }
            for (auto &new_y : new_ys) {
                if (new_y.size() <= 0) {
                    return large_bits();
                }
            }

            ys = new_ys;
            metadata = new_metadata;
        }

        bits challenge_bits = bits(challenge, 256 / 8, 256);
        uint16_t quality_index = challenge_bits.slice(256 - 5).get_value() << 1;

        // Makes sure the output is equal to the first k bits of the challenge
        if (challenge_bits.slice(0, k) == ys[0].slice(0, k)) {
            // Returns quality string, which requires changing proof to plot ordering
            return get_quality_string(k, proof_bits, quality_index);
        } else {
            return large_bits();
        }
    }

private:
    // Compares two lists of k values, a and b. a > b iff max(a) > max(b),
    // if there is a tie, the next largest value is compared.
    bool compare_proof_bits(const large_bits &left, const large_bits &right, uint8_t k) {
        uint16_t size = left.size() / k;
        assert(left.size() == right.size());
        for (int16_t i = size - 1; i >= 0; i--) {
            large_bits left_val = left.slice(k * i, k * (i + 1));
            large_bits right_val = right.slice(k * i, k * (i + 1));
            if (left_val < right_val) {
                return true;
            }
            if (left_val > right_val) {
                return false;
            }
        }
        return false;
    }
};

#endif    // SRC_CPP_VERIFIER_HPP_
