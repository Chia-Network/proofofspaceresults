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

#ifndef SRC_CPP_PROVER_DISK_HPP_
#define SRC_CPP_PROVER_DISK_HPP_

#include <unistd.h>
#include <cstdio>
#include <cmath>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <utility>
#include <algorithm>    // std::min

#include "utilities.hpp"
#include "encoding.hpp"
#include "calculate_bucket.hpp"
#include "hellman.hpp"
#include "plotter_disk.hpp"

// The disk_prover, given a correctly formatted plot file, can efficiently generate valid proofs
// of space, for a given challenge.
class disk_prover {
public:
    // The costructor opens the file, and reads the contents of the file header. The table pointers
    // will be used to find and seek to all seven tables, at the time of proving.
    explicit disk_prover(const std::string &filename) : disk_file(filename, std::ios::in | std::ios::binary) {
        this->filename = filename;
        // 19 bytes  - "Proof of Space Plot" (utf-8)
        // 32 bytes  - unique plot id
        // 1 byte    - k
        // 2 bytes   - format description length
        // x bytes   - format description
        // 2 bytes   - memo length
        // x bytes   - memo

        // Skip the top of file text "Proof of Space Plot"
        disk_file.seekg(19);

        disk_file.read(reinterpret_cast<char *>(this->id), kIdLen);

        uint8_t kbuf[1];
        disk_file.read(reinterpret_cast<char *>(kbuf), 1);
        this->k = kbuf[0];

        uint8_t size_buf[2];
        disk_file.read(reinterpret_cast<char *>(size_buf), 2);
        uint32_t format_description_size = bits(size_buf, 2, 16).get_value();
        uint8_t *format_description_read = new uint8_t[format_description_size];
        disk_file.read(reinterpret_cast<char *>(format_description_read), format_description_size);
        std::string format_str(reinterpret_cast<char *>(format_description_read));

        // We cannot read a plot with a different format version
        if (format_description_size != kFormatDescription.size() ||
            memcmp(format_description_read, kFormatDescription.data(), format_description_size) != 0) {
            throw std::string("Invalid format") + format_str;
        }

        disk_file.read(reinterpret_cast<char *>(size_buf), 2);
        this->memo_size = bits(size_buf, 2, 16).get_value();
        this->memo = new uint8_t[this->memo_size];
        disk_file.read(reinterpret_cast<char *>(this->memo), this->memo_size);

        this->table_begin_pointers = std::vector<uint64_t>(11, 0);
        this->C2 = std::vector<uint64_t>();

        uint8_t pointer_buf[8];
        for (uint8_t i = 1; i < 11; i++) {
            disk_file.read(reinterpret_cast<char *>(pointer_buf), 8);
            this->table_begin_pointers[i] = utilities::eight_bytes_to_int(pointer_buf);
        }

        disk_file.seekg(table_begin_pointers[9]);

        // The list of C2 entries is small enough to keep in memory. When proving, we can
        // read from disk the C1 and C3 entries.
        uint8_t c2_size = (utilities::byte_align(k) / 8);
        uint8_t *c2_buf = new uint8_t[c2_size];
        for (uint i = 0; i < floor((table_begin_pointers[10] - table_begin_pointers[9]) / c2_size) - 1; i++) {
            disk_file.read(reinterpret_cast<char *>(c2_buf), c2_size);
            this->C2.push_back(bits(c2_buf, c2_size, c2_size * 8).slice(0, k).get_value());
        }

        attacker = new attacker_type(pow(2, ((double)k * 2 / 3)), pow(2, ((double)k / 3)), (1LL << k), 5, id);

        attacker->build_table();
        std::cout << "Hellman table complete" << std::endl;
        attacker->load_extra_storage_from_disk(filename, table_begin_pointers[1]);

        delete[] c2_buf;
        delete[] format_description_read;
    }

    ~disk_prover() {
        this->disk_file.close();
        delete attacker;
        delete[] this->memo;
    }

    void get_memo(uint8_t *buffer) {
        memcpy(buffer, memo, this->memo_size);
    }

    void get_id(uint8_t *buffer) {
        memcpy(buffer, id, kIdLen);
    }

    uint8_t size() {
        return k;
    }

    // Reads exactly one line point (pair of two k bit back-pointers) from the given table.
    // The entry at index "position" is read. First, the park index is calculated, then
    // the park is read, and finally, entry deltas are added up to the position that we
    // are looking for.
    uint128_t read_line_point(uint8_t table_index, uint64_t position) {
        uint64_t park_index = floor(position / kEntriesPerPark);
        uint32_t park_size_bits = disk_plotter::calculate_park_size(k, table_index) * 8;
        disk_file.seekg(table_begin_pointers[table_index] + (park_size_bits / 8) * park_index);

        // This is the checkpoint at the beginning of the park
        uint16_t line_point_size_bits = disk_plotter::calculate_line_point_size(k) * 8;
        uint8_t *line_point_bin = new uint8_t[line_point_size_bits / 8];
        disk_file.read(reinterpret_cast<char *>(line_point_bin), line_point_size_bits / 8);
        uint128_t line_point =
            bits(line_point_bin, line_point_size_bits / 8, line_point_size_bits).slice(0, k * 2).get_value();

        // Reads EPP stubs
        uint32_t stubs_size_bits = disk_plotter::calculate_stubs_size(k) * 8;
        uint8_t *stubs_bin = new uint8_t[stubs_size_bits / 8 + 1];
        disk_file.read(reinterpret_cast<char *>(stubs_bin), stubs_size_bits / 8);
        std::vector<uint64_t> stubs;
        stubs.push_back(0);

        for (uint32_t i = 0; i < kEntriesPerPark - 1; i++) {
            park_bits stubs_section = park_bits(stubs_bin + (i * (k - kStubMinusBits)) / 8,
                                                (utilities::byte_align((k - kStubMinusBits)) / 8) + 1,
                                                (utilities::byte_align((k - kStubMinusBits)) / 8 + 1) * 8);
            uint8_t start_bit = (i * (k - kStubMinusBits)) % 8;
            stubs.push_back(stubs_section.slice(start_bit, start_bit + (k - kStubMinusBits)).get_value());
        }

        // Reads EPP deltas
        uint32_t max_deltas_size_bits = disk_plotter::calculate_max_deltas_size(k, table_index) * 8;
        uint8_t *deltas_bin = new uint8_t[max_deltas_size_bits / 8];

        // Reads the size of the encoded deltas object
        uint16_t encoded_deltas_size = 0;
        disk_file.read(reinterpret_cast<char *>(&encoded_deltas_size), sizeof(uint16_t));
        disk_file.read(reinterpret_cast<char *>(deltas_bin), encoded_deltas_size);
        park_bits deltas_park = park_bits(deltas_bin, encoded_deltas_size, encoded_deltas_size * 8);

        // Decodes the deltas
        double R = kRValues[table_index - 1];
        std::vector<uint8_t> deltas = encoding::ans_decode_deltas(deltas_park, kEntriesPerPark - 1, R);
        deltas.insert(deltas.begin(), 1, 0);

        uint128_t sum_deltas = 0;
        uint128_t sum_stubs = 0;
        for (uint32_t i = 0; i < std::min((uint32_t)(position % kEntriesPerPark) + 1, (uint32_t)deltas.size()); i++) {
            sum_deltas += deltas[i];
            sum_stubs += stubs[i];
        }

        uint128_t big_delta = ((uint128_t)1 << (k - kStubMinusBits)) * sum_deltas + sum_stubs;
        uint128_t final_line_point = line_point + big_delta;

        delete[] line_point_bin;
        delete[] stubs_bin;
        delete[] deltas_bin;

        return final_line_point;
    }

    // Given a challenge, returns a quality string, which is 2 adjecent x values,
    // from the 64 value proof. Note that this is more efficient than fetching all
    // 64 x values, which are in different parts of the disk.
    std::vector<large_bits> get_qualities_for_challenge(uint8_t *challenge) {
        // This tells us how many f7 outputs (and therefore proofs) we have for this
        // challenge. The expected value is one proof.
        std::vector<uint64_t> p7_entries = get_p7_entries(challenge);

        if (p7_entries.empty()) {
            disk_file.clear();
            disk_file.sync();
            return std::vector<large_bits>();
        }

        // Qualities are not implemented in the Hellman attack version.
        std::vector<large_bits> qualities;
        for (int i = 0; i < p7_entries.size(); i++)
            qualities.emplace_back(0, 2 * k);
        return qualities;

        // The last 5 bits of the challenge determine which route we take to get to
        // our two x values in the leaves.
        large_bits last_5_bits = large_bits(challenge, 256 / 8, 256).slice(256 - 5);

        for (unsigned long long position : p7_entries) {
            // This inner loop goes from table 6 to table 1, getting the two backpointers,
            // and following one of them.
            for (uint8_t table_index = 6; table_index > 1; table_index--) {
                uint128_t line_point = read_line_point(table_index, position);

                auto xy = encoding::line_point_to_square(line_point);
                assert(xy.first >= xy.second);

                if (last_5_bits.slice(7 - table_index - 1, 7 - table_index).get_value() == 0) {
                    position = xy.second;
                } else {
                    position = xy.first;
                }
            }
            uint128_t new_line_point = read_line_point(1, position);
            auto x1x2 = encoding::line_point_to_square(new_line_point);

            // The final two x values (which are stored in the same location) are returned.
            qualities.push_back(large_bits(x1x2.second, k) + large_bits(x1x2.first, k));
        }
        disk_file.clear();
        disk_file.sync();
        return qualities;
    }

    // Gets the P7 positions of the target f7 entries. Uses the C3 encoded bitmask read from disk.
    // A C3 park is a list of deltas between p7 entries, ANS encoded.
    std::vector<uint64_t> get_p7_positions(uint64_t curr_f7, uint64_t f7, uint64_t curr_p7_pos, uint8_t *bit_mask,
                                           uint16_t encoded_size, uint64_t c1_index) {
        std::vector<uint8_t> deltas = encoding::ans_decode_deltas(large_bits(bit_mask, encoded_size, encoded_size * 8),
                                                                  kCheckpoint1Interval, kC3R);
        std::vector<uint64_t> p7_positions;
        for (uint8_t delta : deltas) {
            if (curr_f7 > f7) {
                break;
            }
            curr_f7 += delta;
            curr_p7_pos += 1;

            if (curr_f7 == f7) {
                p7_positions.push_back(curr_p7_pos);
            }

            // In the last park, we might have extra deltas
            if (curr_p7_pos >= (int64_t)((c1_index + 1) * kCheckpoint1Interval) - 1 ||
                curr_f7 >= (((uint64_t)1) << k)) {
                return p7_positions;
            }
        }
        return p7_positions;
    }

    std::vector<uint64_t> invert_f1(uint64_t x) {
        f1_calculator f(k, id);
        std::vector<uint64_t> res;
        f.reload_key();
        uint64_t y = f.calculate_f(bits(x, k)).get_value();
        uint16_t yl_bid = (y % kBC) / kC;
        uint16_t yl_cid = y % kC;
        uint16_t parity = (y / kBC) % 2;
        uint64_t bucket = y / kBC;
        ++bucket;
        for (uint8_t m = 0; m < kExtraBitsPow; m++) {
            uint16_t target_bid = (yl_bid + m);
            uint16_t target_cid = yl_cid + matching_shifts_c[parity][m];
            if (target_bid >= kB) {
                target_bid -= kB;
            }
            if (target_cid >= kC) {
                target_cid -= kC;
            }
            for (int remainder = target_cid; remainder < kBC; remainder += kC) {
                uint64_t yr_candidate = bucket * kBC + remainder;
                if ((yr_candidate % kBC) / kC == target_bid) {
                    auto inverses = attacker->invert(yr_candidate);
                    for (auto i : inverses)
                        res.push_back(i);
                }
            }
        }
        return res;
    }

    std::vector<std::pair<uint64_t, uint64_t>> invert_f2(uint64_t x0, uint64_t x2) {
        std::vector<uint64_t> inv1 = invert_f1(x0);
        std::vector<uint64_t> inv2 = invert_f1(x2);
        f1_calculator f1(k, id);
        std::vector<std::pair<uint64_t, uint64_t>> res;
        f1.reload_key();
        auto y0 = f1.calculate_f(bits(x0, k));
        auto y2 = f1.calculate_f(bits(x2, k));

        for (auto x1 : inv1) {
            f1.reload_key();
            auto y1 = f1.calculate_f(bits(x1, k));
            for (auto x3 : inv2) {
                fx_calculator fx(k, 2, id);
                f1.reload_key();
                auto y3 = f1.calculate_f(bits(x3, k));
                fx.reload_key();
                plot_entry l_plot_entry {}, r_plot_entry {};
                l_plot_entry.y = fx.calculate_bucket(y0, y1, bits(x0, k), bits(x1, k)).first.get_value();
                r_plot_entry.y = fx.calculate_bucket(y2, y3, bits(x2, k), bits(x3, k)).first.get_value();
                std::vector<plot_entry> bucket_L = {l_plot_entry};
                std::vector<plot_entry> bucket_R = {r_plot_entry};
                if (l_plot_entry.y < r_plot_entry.y && fx.find_matches(bucket_L, bucket_R).size() == 1) {
                    res.emplace_back(x1, x3);
                }
                if (l_plot_entry.y > r_plot_entry.y && fx.find_matches(bucket_R, bucket_L).size() == 1) {
                    res.emplace_back(x1, x3);
                }
            }
        }
        return res;
    }

    large_bits try_all_proofs(std::vector<std::pair<uint64_t, uint64_t>> *inverses, std::vector<bits> xs, int depth,
                              large_bits sol) {
        if (depth == 16) {
            std::vector<bits> proof_vector;
            for (int i = 0; i < 64; i++) {
                uint64_t cur_x = sol.slice_bits_to_int(k * i, k * (i + 1));
                proof_vector.emplace_back(cur_x, k);
            }
            std::vector<large_bits> xs_sorted = reorder_proof(proof_vector);
            if (xs_sorted.size() == 64) {
                sol = large_bits();
                for (int i = 0; i < 64; i++)
                    sol += xs_sorted[i];
                return sol;
            }
            return large_bits();
        }
        for (int i = 0; i < inverses[depth].size(); i++) {
            large_bits new_sol = sol;
            new_sol += xs[2 * depth];
            new_sol += bits(inverses[depth][i].first, k);
            new_sol += xs[2 * depth + 1];
            new_sol += bits(inverses[depth][i].second, k);
            large_bits got_sol = try_all_proofs(inverses, xs, depth + 1, new_sol);
            if (!(got_sol == large_bits()))
                return got_sol;
        }
        return large_bits();
    }

    large_bits find_full_solution(std::vector<bits> known_half) {
        std::vector<std::pair<uint64_t, uint64_t>> inverses[16];
        for (int i = 0; i < 32; i += 2)
            inverses[i / 2] = invert_f2(known_half[i].get_value(), known_half[i + 1].get_value());
        large_bits sol;
        large_bits proof = try_all_proofs(inverses, known_half, 0, sol);
        return proof;
    }

    // Returns P7 table entries (which are positions into table P6), for a given challenge
    std::vector<uint64_t> get_p7_entries(uint8_t *challenge) {
        if (C2.empty()) {
            return std::vector<uint64_t>();
        }
        bits challenge_bits = bits(challenge, 256 / 8, 256);

        // The first k bits determine which f7 matches with the challenge.
        const uint64_t f7 = challenge_bits.slice(0, k).get_value();

        int64_t c1_index = 0;
        bool broke = false;
        uint64_t c2_entry_f = 0;
        // Goes through C2 entries until we find the correct C2 checkpoint. We read each entry,
        // comparing it to our target (f7).
        for (uint64_t c2_entry : C2) {
            c2_entry_f = c2_entry;
            if (f7 < c2_entry) {
                // If we passed our target, go back by one.
                c1_index -= kCheckpoint2Interval;
                broke = true;
                break;
            }
            c1_index += kCheckpoint2Interval;
        }

        if (c1_index < 0) {
            return std::vector<uint64_t>();
        }

        if (!broke) {
            // If we didn't break, go back by one, to get the final checkpoint.
            c1_index -= kCheckpoint2Interval;
        }

        uint32_t c1_entry_size = utilities::byte_align(k) / 8;

        uint8_t *c1_entry_bytes = new uint8_t[c1_entry_size];
        disk_file.seekg(table_begin_pointers[8] + c1_index * utilities::byte_align(k) / 8);

        uint64_t curr_f7 = c2_entry_f;
        uint64_t prev_f7 = c2_entry_f;
        broke = false;
        // Goes through C2 entries until we find the correct C1 checkpoint.
        for (uint64_t start = 0; start < kCheckpoint1Interval; start++) {
            disk_file.read(reinterpret_cast<char *>(c1_entry_bytes), c1_entry_size);
            bits c1_entry = bits(c1_entry_bytes, utilities::byte_align(k) / 8, utilities::byte_align(k));
            uint64_t read_f7 = c1_entry.slice(0, k).get_value();

            if (start != 0 && read_f7 == 0) {
                // We have hit the end of the checkpoint list
                break;
            }
            curr_f7 = read_f7;

            if (f7 < curr_f7) {
                // We have passed the number we are looking for, so go back by one
                curr_f7 = prev_f7;
                c1_index -= 1;
                broke = true;
                break;
            }

            c1_index += 1;
            prev_f7 = curr_f7;
        }
        if (!broke) {
            // We never broke, so go back by one.
            c1_index -= 1;
        }

        uint32_t c3_entry_size = disk_plotter::calculate_c3_size(k);
        uint8_t *bit_mask = new uint8_t[c3_entry_size];

        // Double entry means that our entries are in more than one checkpoint park.
        bool double_entry = f7 == curr_f7 && c1_index > 0;

        uint64_t next_f7;
        uint8_t encoded_size_buf[2];
        uint16_t encoded_size;
        std::vector<uint64_t> p7_positions;
        int64_t curr_p7_pos = c1_index * kCheckpoint1Interval;

        if (double_entry) {
            // In this case, we read the previous park as well as the current one
            c1_index -= 1;
            uint8_t *c1_entry_bytes = new uint8_t[utilities::byte_align(k) / 8];
            disk_file.seekg(table_begin_pointers[8] + c1_index * utilities::byte_align(k) / 8);
            disk_file.read(reinterpret_cast<char *>(c1_entry_bytes), utilities::byte_align(k) / 8);
            bits c1_entry_bits = bits(c1_entry_bytes, utilities::byte_align(k) / 8, utilities::byte_align(k));
            next_f7 = curr_f7;
            curr_f7 = c1_entry_bits.slice(0, k).get_value();

            disk_file.seekg(table_begin_pointers[10] + c1_index * c3_entry_size);

            disk_file.read(reinterpret_cast<char *>(encoded_size_buf), 2);
            encoded_size = bits(encoded_size_buf, 2, 16).get_value();
            disk_file.read(reinterpret_cast<char *>(bit_mask), c3_entry_size - 2);

            p7_positions = get_p7_positions(curr_f7, f7, curr_p7_pos, bit_mask, encoded_size, c1_index);

            disk_file.read(reinterpret_cast<char *>(encoded_size_buf), 2);
            encoded_size = bits(encoded_size_buf, 2, 16).get_value();
            disk_file.read(reinterpret_cast<char *>(bit_mask), c3_entry_size - 2);
            delete[] c1_entry_bytes;

            c1_index++;
            curr_p7_pos = c1_index * kCheckpoint1Interval;
            curr_f7 = next_f7;
            auto second_positions = get_p7_positions(next_f7, f7, curr_p7_pos, bit_mask, encoded_size, c1_index);
            p7_positions.insert(p7_positions.end(), second_positions.begin(), second_positions.end());

        } else {
            disk_file.seekg(table_begin_pointers[10] + c1_index * c3_entry_size);
            disk_file.read(reinterpret_cast<char *>(encoded_size_buf), 2);
            encoded_size = bits(encoded_size_buf, 2, 16).get_value();
            disk_file.read(reinterpret_cast<char *>(bit_mask), c3_entry_size - 2);

            p7_positions = get_p7_positions(curr_f7, f7, curr_p7_pos, bit_mask, encoded_size, c1_index);
        }

        // p7_positions is a list of all the positions into table P7, where the output is equal to f7.
        // If it's empty, no proofs are present for this f7.
        if (p7_positions.empty()) {
            delete[] bit_mask;
            delete[] c1_entry_bytes;
            return std::vector<uint64_t>();
        }

        uint64_t p7_park_size_bytes = utilities::byte_align((k + 1) * kEntriesPerPark) / 8;

        std::vector<uint64_t> p7_entries;

        // Given the p7 positions, which are all adjacent, we can read the pos6 values from table P7.
        uint8_t *p7_park_buf = new uint8_t[p7_park_size_bytes];
        uint64_t park_index = (p7_positions[0] == 0 ? 0 : p7_positions[0]) / kEntriesPerPark;
        disk_file.seekg(table_begin_pointers[7] + park_index * p7_park_size_bytes);
        disk_file.read(reinterpret_cast<char *>(p7_park_buf), p7_park_size_bytes);
        park_bits p7_park = park_bits(p7_park_buf, p7_park_size_bytes, p7_park_size_bytes * 8);
        for (uint64_t i = 0; i < p7_positions[p7_positions.size() - 1] - p7_positions[0] + 1; i++) {
            uint64_t new_park_index = (p7_positions[i]) / kEntriesPerPark;
            if (new_park_index > park_index) {
                disk_file.seekg(table_begin_pointers[7] + new_park_index * p7_park_size_bytes);
                disk_file.read(reinterpret_cast<char *>(p7_park_buf), p7_park_size_bytes);
                p7_park = park_bits(p7_park_buf, p7_park_size_bytes, p7_park_size_bytes * 8);
            }
            uint32_t start_bit_index = (p7_positions[i] % kEntriesPerPark) * (k + 1);

            uint64_t p7_int = p7_park.slice(start_bit_index, start_bit_index + k + 1).get_value();
            p7_entries.push_back(p7_int);
        }

        delete[] bit_mask;
        delete[] c1_entry_bytes;
        delete[] p7_park_buf;

        return p7_entries;
    }

    // Given a challenge, and an index, returns a proof of space. This assumes GetQualities was
    // called, and there are actually proofs present. The index represents which proof to fetch,
    // if there are multiple.
    large_bits get_full_proof(uint8_t *challenge, uint32_t index) {
        std::vector<uint64_t> p7_entries = get_p7_entries(challenge);
        if (p7_entries.empty()) {
            disk_file.clear();
            disk_file.sync();
            throw std::string("No proof of space for this challenge");
        }

        // Gets the 64 leaf x values, concatenated together into a k*64 bit string.
        std::vector<bits> xs = get_inputs(p7_entries[index], 6);
        large_bits attack_proof = find_full_solution(xs);

        disk_file.clear();
        disk_file.sync();
        return attack_proof;
    }

    // Changes a proof of space (64 k bit x values) from plot ordering to proof ordering.
    // Proof ordering: x1..x64 s.t.
    //  f1(x1) m= f1(x2) ... f1(x63) m= f1(x64)
    //  f2(C(x1, x2)) m= f2(C(x3, x4)) ... f2(C(x61, x62)) m= f2(C(x63, x64))
    //  ...
    //  f7(C(....)) == challenge
    //
    // Plot ordering: x1..x64 s.t.
    //  f1(x1) m= f1(x2) || f1(x2) m= f1(x1) .....
    //  For all the levels up to f7
    //  AND x1 < x2, x3 < x4
    //     C(x1, x2) < C(x3, x4)
    //     For all comparisons up to f7
    //     Where a < b is defined as:  max(b) > max(a) where a and b are lists of k bit elements
    std::vector<large_bits> reorder_proof(const std::vector<bits> &xs_input) {
        f1_calculator f1(k, id);
        std::vector<std::pair<bits, bits>> results;
        large_bits xs;

        // Calculates f1 for each of the inputs
        for (uint8_t i = 0; i < 64; i++) {
            results.push_back(f1.calculate_bucket(xs_input[i]));
            xs += std::get<1>(results[i]);
        }

        // The plotter calculates f1..f7, and at each level, decides to swap or not swap. Here, we
        // are doing a similar thing, we swap left and right, such that we end up with proof ordering.
        for (uint8_t table_index = 2; table_index < 8; table_index++) {
            large_bits new_xs;
            // New results will be a list of pairs of (y, metadata), it will decrease in size by 2x
            // at each iteration of the outer loop.
            std::vector<pair<bits, bits>> new_results;
            fx_calculator f(k, table_index, id);
            // Iterates through pairs of things, starts with 64 things, then 32, etc, up to 2.
            for (uint8_t i = 0; i < results.size(); i += 2) {
                std::pair<bits, bits> new_output;
                // Compares the buckets of both ys, to see which one goes on the left, and which
                // one goes on the right
                if (std::get<0>(results[i]).get_value() < std::get<0>(results[i + 1]).get_value()) {
                    new_output =
                        f.calculate_bucket(std::get<0>(results[i]), std::get<0>(results[i + 1]),
                                           std::get<1>(results[i]), std::get<1>(results[i + 1]), /*check=*/true);
                    uint64_t start = (uint64_t)k * i * ((uint64_t)1 << (table_index - 2));
                    uint64_t end = (uint64_t)k * (i + 2) * ((uint64_t)1 << (table_index - 2));
                    new_xs += xs.slice(start, end);
                } else {
                    // Here we switch the left and the right
                    new_output =
                        f.calculate_bucket(std::get<0>(results[i + 1]), std::get<0>(results[i]),
                                           std::get<1>(results[i + 1]), std::get<1>(results[i]), /*check=*/true);
                    uint64_t start = (uint64_t)k * i * ((uint64_t)1 << (table_index - 2));
                    uint64_t start2 = (uint64_t)k * (i + 1) * ((uint64_t)1 << (table_index - 2));
                    uint64_t end = (uint64_t)k * (i + 2) * ((uint64_t)1 << (table_index - 2));
                    new_xs += (xs.slice(start2, end) + xs.slice(start, start2));
                }
                if (std::get<0>(new_output).size() == 0) {
                    return std::vector<large_bits>();
                }
                new_results.push_back(new_output);
            }
            // Advances to the next table
            // xs is a concatenation of all 64 x values, in the current order. Note that at each
            // iteration, we can swap several parts of xs
            results = new_results;
            xs = new_xs;
        }
        std::vector<large_bits> ordered_proof;
        for (uint8_t i = 0; i < 64; i++) {
            ordered_proof.push_back(xs.slice(i * k, (i + 1) * k));
        }
        return ordered_proof;
    }

    // Recursive function to go through the tables on disk, backpropagating and fetching
    // all of the leaves (x values). For example, for depth=5, it fetches the positionth
    // entry in table 5, reading the two backpointers from the line point, and then
    // recursively calling get_inputs for table 4.
    std::vector<bits> get_inputs(uint64_t position, uint8_t depth) {
        uint128_t line_point = read_line_point(depth, position);
        std::pair<uint64_t, uint64_t> xy = encoding::line_point_to_square(line_point);

        if (depth == 2) {
            std::vector<bits> ret;
            ret.emplace_back(xy.second, k);    // y
            ret.emplace_back(xy.first, k);     // x
            return ret;
        } else {
            std::vector<bits> left = get_inputs(xy.second, depth - 1);    // y
            std::vector<bits> right = get_inputs(xy.first, depth - 1);    // x
            left.insert(left.end(), right.begin(), right.end());
            return left;
        }
    }

private:
    std::ifstream disk_file;
    std::string filename;
    uint32_t memo_size;
    uint8_t *memo;
    uint8_t id[kIdLen];    // Unique plot id
    uint8_t k;
    attacker_type *attacker;
    std::vector<uint64_t> table_begin_pointers;
    std::vector<uint64_t> C2;
};

#endif    // SRC_CPP_PROVER_DISK_HPP_
