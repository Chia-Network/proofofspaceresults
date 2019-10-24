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

#ifndef HELLMAN_ATTACK_HPP_
#define HELLMAN_ATTACK_HPP_

#include "bits.hpp"
#include "calculate_bucket.hpp"
#include "pos_constants.hpp"
#include "sorting.hpp"
#include "util.hpp"
#include <random>
#include <set>
#include <vector>

class Attacker {
public:
  explicit Attacker(uint64_t attack_space, uint64_t attack_time, uint64_t n,
                    uint8_t num_tables, uint8_t id[]);
  virtual ~Attacker() {}

  inline std::vector<uint64_t> InvertRealY(uint64_t y);

  inline std::vector<uint64_t> Invert(uint64_t y);

  inline uint64_t EvaluateForward(uint64_t x);

  inline uint64_t GetBucket(uint64_t x);

  // Given attack_space and attack_time from the constructor, it builds the
  // tables.
  inline void BuildTable();

  inline void BuildExtraStorage();

  inline void BuildDiskExtraStorage(std::string filename,
                                    std::vector<uint64_t> &extra_metadata);

  inline void BuildFileExtraStorage(const std::string &filename,
                                    uint8_t *sort_memory,
                                    uint64_t sort_memory_len,
                                    std::vector<uint64_t> &extra_metadata);

#if 0
  inline void LoadExtraStorageFromDisk(const std::string &filename,
                                       uint64_t table1_pos);
#endif

  inline void LoadExtraStorageFromDisk(Disk *disk, uint64_t table1_pos);

  // Given a table and a value, sets lo and
  // hi values to the lowest/highest rows
  // where the value appears.
  inline void FindTableEntry(uint64_t y, int t, int64_t &lo, int64_t &hi);

  inline int ShuffleBits(int perm_idx, int t, uint64_t x);

  // Returns -1 in case of a false alarm,
  // otherwise returns the inverse, given
  // the chain begin.
  inline int CheckChain(uint64_t root, uint64_t y, uint64_t expected_pos,
                        uint64_t t);

private:
  uint64_t attack_space_;
  uint64_t attack_time_;
  uint64_t n_;
  uint8_t num_tables_;
  uint8_t num_bits_;
  std::mt19937 rng_;
  F1Calculator f1_;
  std::vector<std::vector<int>> shuffle_permutation_;

  std::vector<std::vector<std::pair<uint64_t, uint64_t>>> tables_;
  std::vector<int> pad_;
  std::vector<std::pair<uint64_t, uint64_t>> extra_storage_inverses_;

  static inline uint8_t GetNumBits(uint64_t n) {
    uint8_t num_bits;
    for (num_bits = 0; (1ull << num_bits) < n; ++num_bits)
      ;
    return num_bits;
  }

  static constexpr int kRNG = 12121;
};

///////////////////////////////////////////////////////////////////////////////
Attacker::Attacker(uint64_t attack_space, uint64_t attack_time, uint64_t n,
                   u_int8_t num_tables, uint8_t *id)
    : attack_space_{attack_space}, attack_time_{attack_time}, n_{n},
      num_tables_{num_tables}, num_bits_(GetNumBits(n)), rng_(kRNG),
      f1_(GetNumBits(n), id) {

  for (auto i = 0ull; i < attack_time_; ++i) {
    std::vector<int> cur_perm;
    cur_perm.reserve(num_bits_);
    for (auto i = 0u; i < num_bits_; ++i)
      cur_perm.push_back(i);

    std::shuffle(cur_perm.begin(), cur_perm.end(), rng_);
    shuffle_permutation_.push_back(cur_perm);
  }
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Attacker::EvaluateForward(uint64_t val) {
  Bits x(val, num_bits_);
  f1_.ReloadKey();
  Bits bucket = f1_.CalculateF(x);
  return bucket.SliceBitsToInt(0, num_bits_);
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Attacker::GetBucket(uint64_t val) {
  Bits x(val, num_bits_);
  f1_.ReloadKey();
  Bits bucket = f1_.CalculateF(x);
  return bucket.GetValue() / kBC;
}

///////////////////////////////////////////////////////////////////////////////
void Attacker::BuildTable() {
  std::uniform_int_distribution<int> dis(0, n_);
  std::vector<uint64_t> table_begin;
  for (auto i = 0ull; i < n_; i += (attack_space_ * num_tables_)) {
    auto j = i + (attack_space_ * num_tables_);
    if (j > n_ - 1)
      j = n_ - 1;
    std::vector<uint64_t> perm;
    for (auto k = i; k <= j; k++)
      perm.push_back(k);
    std::shuffle(perm.begin(), perm.end(), rng_);
    uint64_t num_buckets = n_ / (attack_space_ * num_tables_);
    uint64_t choose = attack_space_ * num_tables_ / num_buckets;
    for (auto k = 0ull; k < choose; k++)
      table_begin.push_back(perm[k]);
  }
  std::cout << "\t\tTotal distinct tables start elements: "
            << table_begin.size()
            << " Needed: " << (attack_space_ * num_tables_) << "\n";
  auto idx = 0ul;
  for (auto i = 0ull; i < (2 * attack_time_); ++i)
    pad_.push_back(dis(rng_));
  for (auto t = 0ull; t < num_tables_; ++t) {
    std::vector<std::pair<uint64_t, uint64_t>> table;
    for (auto i = 0ull; i < attack_space_; ++i) {
      int x_init = table_begin[idx++];
      if (idx == table_begin.size())
        idx = 0;
      int x_fin = x_init;
      for (auto j = 0ull; j < attack_time_; ++j) {
        x_fin = EvaluateForward(x_fin);
        x_fin = ShuffleBits(j, t, x_fin);
      }
      table.push_back({x_fin, x_init});
      // std::cout << x_init << " " << x_fin << "\n";
    }
    std::sort(table.begin(), table.end());
    tables_.push_back(table);
  }
}

///////////////////////////////////////////////////////////////////////////////
void Attacker::FindTableEntry(uint64_t y, int t, int64_t &lo, int64_t &hi) {
  int64_t left = 0, right = tables_[t].size() - 1;
  lo = -1, hi = -1;
  while (left <= right) {
    int middle = (left + right) / 2;
    if (tables_[t][middle].first == y) {
      lo = middle;
      right = middle - 1;
      continue;
    }
    if (tables_[t][middle].first < y)
      left = middle + 1;
    else
      right = middle - 1;
  }
  if (lo == -1)
    return;
  left = 0;
  right = tables_[t].size() - 1;
  while (left <= right) {
    int64_t middle = (left + right) / 2;
    if (tables_[t][middle].first == y) {
      hi = middle;
      left = middle + 1;
      continue;
    }
    if (tables_[t][middle].first < y)
      left = middle + 1;
    else
      right = middle - 1;
  }
}

///////////////////////////////////////////////////////////////////////////////
int Attacker::CheckChain(uint64_t root, uint64_t y, uint64_t expected_pos,
                         uint64_t t) {
  for (auto i = 0ul; i <= expected_pos; ++i) {
    int ant = root;
    root = EvaluateForward(root);
    root = ShuffleBits(i, t, root);
    if (root == y && i == expected_pos) {
      return ant;
    }
  }
  return -1;
}

///////////////////////////////////////////////////////////////////////////////
std::vector<uint64_t> Attacker::InvertRealY(uint64_t y) {
  std::vector<uint64_t> results;
  for (int64_t i = attack_time_ - 1; i >= 0; --i) {
    for (int64_t t = 0; t < num_tables_; ++t) {
      int64_t y_fin = ShuffleBits(i, t, y);
      for (uint64_t j = i + 1; j < attack_time_; ++j) {
        y_fin = EvaluateForward(y_fin);
        y_fin = ShuffleBits(j, t, y_fin);
      }
      int64_t lo, hi;
      FindTableEntry(y_fin, t, lo, hi);
      if (lo != -1) {
        for (int row = lo; row <= hi; ++row) {
          int inv =
              CheckChain(tables_[t][row].second, ShuffleBits(i, t, y), i, t);
          if (inv != -1) {
            results.push_back(inv);
          }
        }
      }
    }
  }
  return results;
}

///////////////////////////////////////////////////////////////////////////////
std::vector<uint64_t> Attacker::Invert(uint64_t y) {
  std::vector<uint64_t> results;
  std::set<uint64_t> fount;
  int64_t left = 0, right = extra_storage_inverses_.size() - 1, low = -1;
  f1_.ReloadKey();
  while (left <= right) {
    uint64_t med = (left + right) / 2;
    if (extra_storage_inverses_[med].first == y) {
      right = med - 1;
      low = med;
    }
    if (extra_storage_inverses_[med].first < y) {
      left = med + 1;
    }
    if (extra_storage_inverses_[med].first > y) {
      right = med - 1;
    }
  }
  if (low != -1) {
    for (uint64_t i = low; extra_storage_inverses_[i].first == y; ++i) {
      uint64_t x = extra_storage_inverses_[i].second;
      results.push_back(x);
    }
  }

  // Cut the extra bits.
  uint64_t real_y = y >> 5;
  std::vector<uint64_t> sols = InvertRealY(real_y);
  for (auto val : sols) {
    if (fount.find(val) == fount.end()) {
      fount.insert(val);
      if (f1_.CalculateF(Bits(val, num_bits_)).GetValue() == y)
        results.push_back(val);
    }
  }
  return results;
}

///////////////////////////////////////////////////////////////////////////////
int Attacker::ShuffleBits(int perm_idx, int t, uint64_t x) {
  int res = 0;
  for (auto i = 0ul; i < num_bits_; ++i)
    if (x & (1 << i)) {
      int pos = shuffle_permutation_[perm_idx][i];
      res |= (1 << pos);
    }
  return res ^ pad_[perm_idx xor t];
}

///////////////////////////////////////////////////////////////////////////////
void Attacker::BuildExtraStorage() {
  for (uint64_t low = 0; low < n_; low += (attack_space_ * num_tables_)) {
    int high = std::min(n_ - 1, low + attack_space_ * num_tables_ - 1);
    std::vector<bool> found_x(attack_space_ * num_tables_);
    for (uint64_t t = 0; t < num_tables_; ++t) {
      for (uint64_t row = 0; row < attack_space_; ++row) {
        int x_fin = tables_[t][row].second;
        for (uint64_t j = 0; j < attack_time_; ++j) {
          if (low <= x_fin && x_fin <= high)
            found_x[x_fin - low] = true;
          x_fin = EvaluateForward(x_fin);
          x_fin = ShuffleBits(j, t, x_fin);
        }
      }
    }
    for (int j = low; j <= high; ++j) {
      if (!found_x[j - low])
        extra_storage_inverses_.push_back(
            {f1_.CalculateF(Bits(j, num_bits_)).GetValue(), j});
    }
    std::cout << "\t\tDone one bucket of extra storage using size = "
              << (attack_space_ * num_tables_) << "\n";
  }
  std::cout << "\t\tNumber of bits:" << int{num_bits_} << "\n";
  std::sort(extra_storage_inverses_.begin(), extra_storage_inverses_.end());
  std::cout << "\t\tExtra elements stored: " << extra_storage_inverses_.size()
            << "\n";
  std::cout << "\t\tHellman table accuracy = "
            << ((double)((1LL << num_bits_) - extra_storage_inverses_.size())) /
                   (1LL << num_bits_)
            << "\n";
}

///////////////////////////////////////////////////////////////////////////////
void Attacker::BuildDiskExtraStorage(std::string filename,
                                     std::vector<uint64_t> &extra_metadata) {

  // create empty file
  FileDisk disk(filename, 0);
  disk.Open();
  std::ostream *writer = disk.WriteHandle();

  uint8_t entry_len = Util::ByteAlign(num_bits_) / 8;
  uint8_t buf[entry_len];
  std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);
  uint64_t entries_written = 0;
  uint8_t *memory = new uint8_t[kSortMemorySizeTotal];
  uint32_t bucket_log = floor(log2(kNumSortBuckets));

  for (uint64_t t = 0; t < num_tables_; ++t) {
    for (uint64_t row = 0; row < attack_space_; ++row) {
      uint64_t x_fin = tables_[t][row].second;
      for (uint64_t j = 0; j < attack_time_; ++j) {
        Bits to_write(x_fin, num_bits_);
        to_write.ToBytes(buf);
        writer->write((const char *)buf, entry_len);
        x_fin = EvaluateForward(x_fin);
        x_fin = ShuffleBits(j, t, x_fin);
        bucket_sizes[Util::ExtractNum(buf, entry_len, 0, bucket_log)] += 1;
        entries_written++;
      }
    }
  }
  writer->flush();

  Sort sorter(&disk);
  uint64_t begin_byte = 0;
  uint64_t spare_begin = begin_byte + (entry_len * (entries_written + 1));
  DSort param =
      sorter.makeParam(begin_byte, spare_begin, entry_len, 0, bucket_sizes,
                       memory, Sort::kSortMemorySize, 1);
  sorter.diskSort(param);
  disk.Close();

  std::ifstream reader(filename, std::fstream::in | std::fstream::binary);
  uint64_t prev_x;
  for (uint64_t i = 0; i < entries_written; i++) {
    reader.read(reinterpret_cast<char *>(buf), entry_len);
    uint64_t cur_x = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
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
  uint64_t max_x = (1LL << num_bits_) - 1;
  if (prev_x != max_x)
    for (uint64_t i = prev_x + 1; i <= max_x; i++)
      extra_metadata.push_back(i);
  std::cout << "\t\tDisk Extra Storage count = " << extra_metadata.size()
            << "\n";
  std::cout << "\t\tHellman table accuracy = "
            << ((double)((1LL << num_bits_) - extra_metadata.size())) /
                   (1LL << num_bits_)
            << "\n";

  delete[] memory;
  reader.close();
}

///////////////////////////////////////////////////////////////////////////////
void Attacker::BuildFileExtraStorage(const std::string &filename,
                                     uint8_t *sort_mem, uint64_t sort_mem_size,
                                     std::vector<uint64_t> &extra_metadata) {

  // create empty file
  FileDisk disk(filename, 0);
  disk.Open();
  std::ostream *writer = disk.WriteHandle();

  uint8_t entry_len = Util::ByteAlign(num_bits_) / 8;
  uint8_t buf[entry_len];
  std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);
  uint64_t entries_written = 0;
  uint32_t bucket_log = kSortBucketsLog;

  for (uint64_t t = 0; t < num_tables_; ++t) {
    for (uint64_t row = 0; row < attack_space_; ++row) {
      uint64_t x_fin = tables_[t][row].second;
      for (uint64_t j = 0; j < attack_time_; ++j) {
        Bits to_write(x_fin, num_bits_);
        to_write.ToBytes(buf);
        writer->write((const char *)buf, entry_len);
        x_fin = EvaluateForward(x_fin);
        x_fin = ShuffleBits(j, t, x_fin);
        bucket_sizes[Util::ExtractNum(buf, entry_len, 0, bucket_log)] += 1;
        entries_written++;
      }
    }
  }
  writer->flush();

  Sort sorter(&disk);
  uint64_t begin_byte = 0;
  uint64_t spare_begin = begin_byte + (entry_len * (entries_written + 1));
  DSort param = sorter.makeParam(begin_byte, spare_begin, entry_len, 0,
                                 bucket_sizes, sort_mem, sort_mem_size, 1);
  sorter.diskSort(param);
  std::istream *reader = disk.ReadHandle();

  uint64_t prev_x{0};
  for (uint64_t i = 0; i < entries_written; i++) {
    reader->read(reinterpret_cast<char *>(buf), entry_len);
    uint64_t cur_x = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
    if (i == 0) {
      for (auto j = 0ul; j < cur_x; j++)
        extra_metadata.push_back(j);
      prev_x = cur_x;
      continue;
    }
    for (uint64_t j = prev_x + 1; j < cur_x; j++)
      extra_metadata.push_back(j);
    assert(cur_x >= prev_x);
    prev_x = cur_x;
  }
  uint64_t max_x = (1LL << num_bits_) - 1;
  if (prev_x != max_x)
    for (uint64_t i = prev_x + 1; i <= max_x; i++)
      extra_metadata.push_back(i);
  std::cout << "\t\tDisk Extra Storage count = " << extra_metadata.size()
            << "\n";
  std::cout << "\t\tHellman table accuracy = "
            << ((double)((1LL << num_bits_) - extra_metadata.size())) /
                   (1LL << num_bits_)
            << "\n";

  disk.Close();
}

#if 0
///////////////////////////////////////////////////////////////////////////////
void Attacker::LoadExtraStorageFromDisk(const std::string &filename,
                                        uint64_t table1_pos) {
  std::ifstream reader(filename, std::fstream::in | std::fstream::binary);
  reader.seekg(table1_pos);
  uint8_t entry_len = Util::ByteAlign(num_bits_) / 8;
  uint8_t buf[entry_len];
  reader.read(reinterpret_cast<char *>(buf), entry_len);
  uint64_t count = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
  f1_.ReloadKey();
  for (uint64_t i = 0; i < count; i++) {
    reader.read(reinterpret_cast<char *>(buf), entry_len);
    uint64_t x = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
    extra_storage_inverses_.push_back(
        {f1_.CalculateF(Bits(x, num_bits_)).GetValue(), x});
  }
  std::cout << "Done loading " << extra_storage_inverses_.size()
            << " elements into Extra Storage memory!\n";
  std::sort(extra_storage_inverses_.begin(), extra_storage_inverses_.end());
}
#endif

///////////////////////////////////////////////////////////////////////////////
void Attacker::LoadExtraStorageFromDisk(Disk *disk, uint64_t table1_pos) {
  std::istream *reader = disk->ReadHandle(table1_pos);

  uint8_t entry_len = Util::ByteAlign(num_bits_) / 8;
  uint8_t buf[entry_len];
  reader->read(reinterpret_cast<char *>(buf), entry_len);
  uint64_t count = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
  f1_.ReloadKey();
  for (uint64_t i = 0; i < count; i++) {
    reader->read(reinterpret_cast<char *>(buf), entry_len);
    uint64_t x = Util::SliceInt64FromBytes(buf, entry_len, 0, num_bits_);
    extra_storage_inverses_.push_back(
        {f1_.CalculateF(Bits(x, num_bits_)).GetValue(), x});
  }
  std::cout << "\t\tDone loading " << extra_storage_inverses_.size()
            << " elements into Extra Storage memory!\n";
  std::sort(extra_storage_inverses_.begin(), extra_storage_inverses_.end());
}

#endif // HELLMAN_ATTACK_HPP_
