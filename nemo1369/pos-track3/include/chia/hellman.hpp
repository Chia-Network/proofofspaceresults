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

#ifndef TRACK3_HELLMAN_HPP_
#define TRACK3_HELLMAN_HPP_

#include <random>
#include <set>
#include <vector>

#include "pos_constants.hpp"
#include "calculate_bucket.hpp"
#include "sort_on_disk.hpp"
#include "bits.hpp"
#include "utilities.hpp"

using namespace std;

class attacker_type {
public:
    attacker_type(uint64_t attack_space, uint64_t attack_time, uint64_t n, int num_tables, uint8_t id[]);

    std::vector<uint64_t> invert_real_y(uint64_t y);

    std::vector<uint64_t> invert(uint64_t y);

    uint64_t evaluate_forward(uint64_t input);

    uint64_t get_bucket(uint64_t input);

    // Given attack_space and attack_time from the constructor, it builds the tables.
    void build_table();

    void build_extra_storage();

    void build_disk_extra_storage(const string &filename, std::vector<uint64_t> &extra_metadata);

    void load_extra_storage_from_disk(const string &filename, uint64_t table1_pos);

    // Given a table and a value, sets lo and hi values to the lowest/highest rows
    // where the value appears.
    void find_table_entry(uint64_t y, int t, int64_t &lo, int64_t &hi);

    int shuffle_bits(int perm_idx, int t, uint64_t x);

    // Returns -1 in case of a false alarm, otherwise returns the inverse, given the chain begin.
    int check_chain(uint64_t root, uint64_t y, uint64_t expected_pos, uint64_t t);

    ~attacker_type() {
    }

private:
    uint8_t num_bits;
    uint64_t attack_space;
    uint64_t attack_time;
    uint64_t n;
    uint8_t num_tables;
    f1_calculator f1;
    std::vector<std::vector<pair<uint64_t, uint64_t>>> tables;
    std::vector<int> pad;
    std::vector<std::vector<int>> shuffle_permutation;
    std::vector<pair<uint64_t, uint64_t>> extra_storage_inverses;

    mt19937 rng;

    uint8_t get_num_bits(int input) {
        uint8_t num_bits;
        for (num_bits = 0; (1 << num_bits) < input; ++num_bits)
            ;
        return num_bits;
    }
};

attacker_type::attacker_type(uint64_t attack_space, uint64_t attack_time, uint64_t n, int num_tables, uint8_t id[]) :
    f1(get_num_bits(n), id), rng(12121) {
    this->attack_space = attack_space;
    this->attack_time = attack_time;
    this->num_tables = num_tables;
    this->n = n;
    num_bits = get_num_bits(n);

    for (int i = 0; i < attack_time; ++i) {
        std::vector<int> cur_perm;
        for (int i = 0; i < num_bits; ++i)
            cur_perm.push_back(i);
        shuffle(cur_perm.begin(), cur_perm.end(), rng);
        shuffle_permutation.push_back(cur_perm);
    }
}

uint64_t attacker_type::evaluate_forward(uint64_t input) {
    bits x(input, num_bits);
    f1.reload_key();
    bits bucket = f1.calculate_f(x);
    return bucket.slice_bits_to_int(0, num_bits);
}

uint64_t attacker_type::get_bucket(uint64_t input) {
    bits x(input, num_bits);
    f1.reload_key();
    bits bucket = f1.calculate_f(x);
    return bucket.get_value() / kBC;
}

void attacker_type::build_table() {
    std::uniform_int_distribution<int> dis(0, n);
    std::vector<uint64_t> table_begin;
    for (int i = 0; i < n; i += attack_space * num_tables) {
        int j = i + attack_space * num_tables;
        if (j > n - 1)
            j = n - 1;
        std::vector<uint64_t> perm;
        for (int k = i; k <= j; k++)
            perm.push_back(k);
        shuffle(perm.begin(), perm.end(), rng);
        uint64_t num_buckets = n / (attack_space * num_tables);
        uint64_t choose = attack_space * num_tables / num_buckets;
        for (int k = 0; k < choose; k++)
            table_begin.push_back(perm[k]);
    }
    std::cout << "Total distinct tables start elements: " << table_begin.size()
              << " Needed: " << attack_space * num_tables << "\n";
    int idx = 0;
    for (int i = 0; i < 2 * attack_time; ++i)
        pad.push_back(dis(rng));
    for (int t = 0; t < num_tables; ++t) {
        std::vector<pair<uint64_t, uint64_t>> table;
        for (int i = 0; i < attack_space; ++i) {
            int x_init = table_begin[idx++];
            if (idx == table_begin.size())
                idx = 0;
            int x_fin = x_init;
            for (int j = 0; j < attack_time; ++j) {
                x_fin = evaluate_forward(x_fin);
                x_fin = shuffle_bits(j, t, x_fin);
            }
            table.emplace_back(x_fin, x_init);
            // std::cout << x_init << " " << x_fin << "\n";
        }
        sort(table.begin(), table.end());
        tables.push_back(table);
    }
}

void attacker_type::find_table_entry(uint64_t y, int t, int64_t &lo, int64_t &hi) {
    int64_t left = 0, right = tables[t].size() - 1;
    lo = -1, hi = -1;
    while (left <= right) {
        int middle = (left + right) / 2;
        if (tables[t][middle].first == y) {
            lo = middle;
            right = middle - 1;
            continue;
        }
        if (tables[t][middle].first < y)
            left = middle + 1;
        else
            right = middle - 1;
    }
    if (lo == -1)
        return;
    left = 0;
    right = tables[t].size() - 1;
    while (left <= right) {
        int64_t middle = (left + right) / 2;
        if (tables[t][middle].first == y) {
            hi = middle;
            left = middle + 1;
            continue;
        }
        if (tables[t][middle].first < y)
            left = middle + 1;
        else
            right = middle - 1;
    }
}

int attacker_type::check_chain(uint64_t root, uint64_t y, uint64_t expected_pos, uint64_t t) {
    for (int i = 0; i <= expected_pos; ++i) {
        int ant = root;
        root = evaluate_forward(root);
        root = shuffle_bits(i, t, root);
        if (root == y && i == expected_pos) {
            return ant;
        }
    }
    return -1;
}

std::vector<uint64_t> attacker_type::invert_real_y(uint64_t y) {
    std::vector<uint64_t> results;
    for (int64_t i = attack_time - 1; i >= 0; --i) {
        for (int64_t t = 0; t < num_tables; ++t) {
            int64_t y_fin = shuffle_bits(i, t, y);
            for (uint64_t j = i + 1; j < attack_time; ++j) {
                y_fin = evaluate_forward(y_fin);
                y_fin = shuffle_bits(j, t, y_fin);
            }
            int64_t lo, hi;
            find_table_entry(y_fin, t, lo, hi);
            if (lo != -1) {
                for (int row = lo; row <= hi; ++row) {
                    int inv = check_chain(tables[t][row].second, shuffle_bits(i, t, y), i, t);
                    if (inv != -1) {
                        results.push_back(inv);
                    }
                }
            }
        }
    }
    return results;
}

std::vector<uint64_t> attacker_type::invert(uint64_t y) {
    std::vector<uint64_t> results;
    set<uint64_t> fount;
    int64_t left = 0, right = extra_storage_inverses.size() - 1, low = -1;
    f1.reload_key();
    while (left <= right) {
        uint64_t med = (left + right) / 2;
        if (extra_storage_inverses[med].first == y) {
            right = med - 1;
            low = med;
        }
        if (extra_storage_inverses[med].first < y) {
            left = med + 1;
        }
        if (extra_storage_inverses[med].first > y) {
            right = med - 1;
        }
    }
    if (low != -1) {
        for (uint64_t i = low; extra_storage_inverses[i].first == y; ++i) {
            uint64_t x = extra_storage_inverses[i].second;
            results.push_back(x);
        }
    }

    // Cut the extra bits.
    uint64_t real_y = y >> 5;
    std::vector<uint64_t> sols = invert_real_y(real_y);
    for (auto val : sols) {
        if (fount.find(val) == fount.end()) {
            fount.insert(val);
            if (f1.calculate_f(bits(val, num_bits)).get_value() == y)
                results.push_back(val);
        }
    }
    return results;
}

int attacker_type::shuffle_bits(int perm_idx, int t, uint64_t x) {
    int res = 0;
    for (int i = 0; i < num_bits; ++i)
        if (x & (1 << i)) {
            int pos = shuffle_permutation[perm_idx][i];
            res |= (1 << pos);
        }
    return res ^ pad[perm_idx xor t];
}

void attacker_type::build_extra_storage() {
    for (uint64_t low = 0; low < n; low += attack_space * num_tables) {
        int high = min(n - 1, low + attack_space * num_tables - 1);
        std::vector<bool> found_x(attack_space * num_tables);
        for (uint64_t t = 0; t < num_tables; ++t) {
            for (uint64_t row = 0; row < attack_space; ++row) {
                int x_fin = tables[t][row].second;
                for (uint64_t j = 0; j < attack_time; ++j) {
                    if (low <= x_fin && x_fin <= high)
                        found_x[x_fin - low] = true;
                    x_fin = evaluate_forward(x_fin);
                    x_fin = shuffle_bits(j, t, x_fin);
                }
            }
        }
        for (int j = low; j <= high; ++j) {
            if (!found_x[j - low])
                extra_storage_inverses.emplace_back(f1.calculate_f(bits(j, num_bits)).get_value(), j);
        }
        std::cout << "Done one bucket of extra storage using size = " << attack_space * num_tables << "\n";
    }
    std::cout << "Number of bits:" << (int)num_bits << "\n";
    sort(extra_storage_inverses.begin(), extra_storage_inverses.end());
    std::cout << "Extra elements stored: " << extra_storage_inverses.size() << "\n";
    std::cout << "Hellman table accuracy = "
              << ((double)((1LL << num_bits) - extra_storage_inverses.size())) / (1LL << num_bits) << "\n";
}

void attacker_type::build_disk_extra_storage(const string &filename, std::vector<uint64_t> &extra_metadata) {
    std::ofstream writer(filename, std::ios::in | std::ios::out | std::ios::binary);
    uint8_t entry_len = utilities::byte_align(num_bits) / 8;
    uint8_t buf[entry_len];
    std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);
    uint64_t entries_written = 0;
    uint8_t *memory = new uint8_t[kMemorySize];
    uint32_t bucket_log = floor(log2(kNumSortBuckets));

    for (uint64_t t = 0; t < num_tables; ++t) {
        for (uint64_t row = 0; row < attack_space; ++row) {
            uint64_t x_fin = tables[t][row].second;
            for (uint64_t j = 0; j < attack_time; ++j) {
                bits to_write(x_fin, num_bits);
                to_write.to_bytes(buf);
                writer.write((const char *)buf, entry_len);
                x_fin = evaluate_forward(x_fin);
                x_fin = shuffle_bits(j, t, x_fin);
                bucket_sizes[sort_on_disk_utils::extract_num(buf, entry_len, 0, bucket_log)] += 1;
                entries_written++;
            }
        }
    }

    writer.flush();
    writer.close();

    file_disk d(filename);
    uint64_t begin_byte = 0;
    uint64_t spare_begin = begin_byte + (entry_len * (entries_written + 1));
    sorting::sort_on_disk(d, begin_byte, spare_begin, entry_len, 0, bucket_sizes, memory, kMemorySize, /*quicksort=*/1);
    d.Close();

    std::ifstream reader(filename, std::fstream::in | std::fstream::binary);
    uint64_t prev_x;
    for (uint64_t i = 0; i < entries_written; i++) {
        reader.read(reinterpret_cast<char *>(buf), entry_len);
        uint64_t cur_x = utilities::slice_int64_from_bytes(buf, entry_len, 0, num_bits);
        if (i == 0) {
            for (int j = 0; j < cur_x; j++)
                extra_metadata.push_back(j);
            prev_x = cur_x;
            continue;
        }
        for (uint64_t j = prev_x + 1; j < cur_x; j++)
            extra_metadata.push_back(j);
        assert(cur_x >= prev_x);
        prev_x = cur_x;
    }
    uint64_t max_x = (1LL << num_bits) - 1;
    if (prev_x != max_x)
        for (uint64_t i = prev_x + 1; i <= max_x; i++)
            extra_metadata.push_back(i);
    std::cout << "Disk Extra Storage count = " << extra_metadata.size() << "\n";
    std::cout << "Hellman table accuracy = "
              << ((double)((1LL << num_bits) - extra_metadata.size())) / (1LL << num_bits) << "\n";

    delete[] memory;
    reader.close();
}

void attacker_type::load_extra_storage_from_disk(const string &filename, uint64_t table1_pos) {
    std::ifstream reader(filename, std::fstream::in | std::fstream::binary);
    reader.seekg(table1_pos);
    uint8_t entry_len = utilities::byte_align(num_bits) / 8;
    uint8_t buf[entry_len];
    reader.read(reinterpret_cast<char *>(buf), entry_len);
    uint64_t count = utilities::slice_int64_from_bytes(buf, entry_len, 0, num_bits);
    f1.reload_key();
    for (uint64_t i = 0; i < count; i++) {
        reader.read(reinterpret_cast<char *>(buf), entry_len);
        uint64_t x = utilities::slice_int64_from_bytes(buf, entry_len, 0, num_bits);
        extra_storage_inverses.emplace_back(f1.calculate_f(bits(x, num_bits)).get_value(), x);
    }
    std::cout << "Done loading " << extra_storage_inverses.size() << " elements into Extra Storage memory!\n";
    std::sort(extra_storage_inverses.begin(), extra_storage_inverses.end());
}

#endif    // TRACK3_HELLMAN_HPP_
