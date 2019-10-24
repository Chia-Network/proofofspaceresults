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

#ifndef PLOTTER_DISK_HPP_
#define PLOTTER_DISK_HPP_

#include <cstdio>  // BUFSIZ
#include <fcntl.h> // open
#include <stdio.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "calculate_bucket.hpp"
#include "encoding.hpp"
#include "pos_constants.hpp"

#include "sorting.hpp"
#include "util.hpp"

using Encoder = FPCEncoder;
using PlotDisk = MemoryMapMioDisk;

// Constants that are only relevant for the plotting process.
// Other constants can be found in pos_constants.hpp

// Number of buckets to use for SortOnDisk.
constexpr uint32_t kNumSortBuckets = 16;
constexpr uint32_t kSortBucketsLog =
    static_cast<uint32_t>(floor(log2(kNumSortBuckets)));

// During backprop and compress, the write pointer is ahead of the read pointer
// Note that the large the offset, the higher these values must be
constexpr uint32_t kReadMinusWrite = 2048;
constexpr uint32_t kCachedPositionsSize = 8192;

// Distance between matching entries is stored in the offset
constexpr uint32_t kOffsetSize = 11;

// Max matches a single entry can have, used for hardcoded memory allocation
constexpr uint32_t kMaxMatchesSingleEntry = 30;

// Plot file header and its size.
static const inline std::string kHeaderText{"Proof of Space Plot"};
constexpr uint8_t kHeaderTextLen = 19;

// Total memory required for sorting.
constexpr size_t kSortMemorySizeTotal =
    (Sort::kSortMemorySize + PlotDisk::kStreamBufferSize);

///////////////////////////////////////////////////////////////////////////////
/// \brief The Phase3Results struct
/// Results of phase 3. These are passed into Phase 4, so the checkpoint tables
/// can be properly built.
///
struct Phase3Results {
  // Pointers to each table start byte in the final file
  std::vector<uint64_t> final_table_begin_pointers;
  // Number of entries written for f7
  uint64_t final_entries_written;
  uint32_t right_entry_size_bits;

  uint32_t header_size;
};

///////////////////////////////////////////////////////////////////////////////
/// \brief The PlotTable struct - contains plot table details.
///
struct PlotTable {
  uint8_t id;         /// id equals to table index in table vector
  uint64_t begin;     /// file offset into table begin
  uint32_t entry_len; /// entry length in bytes
  uint64_t entry_cnt; /// num of entries
  uint64_t size;      /// total table size in bytes (entry_len * entry_cnt)

  friend std::ostream &operator<<(std::ostream &out, const PlotTable &t) {
    out << "\tTable " << int{t.id} << ": [0x" << std::hex << t.begin << std::dec
        << ", " << t.entry_len << ", " << t.entry_cnt << ", " << t.size << "]"
        << std::endl;
    return out;
  }
};

#ifdef USE_HELLMAN_ATTACK
#include "hellman_attack.hpp"
#endif

///////////////////////////////////////////////////////////////////////////////
/// \brief The DiskPlotter class
///
class DiskPlotter {
public:
  DiskPlotter() {}

  virtual ~DiskPlotter() {}

  // This method creates a plot on disk with the filename. A temporary file,
  // "plotting" + filename, is created and will be larger than the final plot
  // file.
  /////////////////////////////////////////////////////////////////////////////
  void CreatePlotDisk(std::string filename, uint8_t k, uint8_t *memo,
                      uint32_t memo_len, uint8_t *id, uint32_t id_len) {

    assert(id_len == kIdLen);
    assert(k >= kMinPlotSize);
    assert(k <= kMaxPlotSize);

    std::cout << "Starting plotting progress into file " << filename << "."
              << std::endl;
    std::cout << "Memo: " << Util::HexStr(memo, memo_len) << std::endl;
    std::cout << "ID: " << Util::HexStr(id, id_len) << std::endl;
    std::cout << "Plot size is: " << static_cast<int>(k) << std::endl;
    uint64_t max_workspace = GetMaxWorkspace(k);
    std::cout << "Max workspace is: " << (max_workspace * 1.0 / 1_GB) << " GB"
              << std::endl;

    // initialize temp and final plot file
    std::string plot_filename = filename + ".tmp";
    temp_ = std::make_unique<PlotDisk>(plot_filename, max_workspace,
                                       Disk::AccessMode::ReadWrite);
    temp_.get()->Open();
    plot_ = std::make_unique<FileDisk>(filename, 0);

    // allocate memory for sorting
    sort_memory_ = std::make_unique<uint8_t[]>(kSortMemorySizeTotal);

    first_line_point_bytes_ =
        std::make_unique<uint8_t[]>(CalculateLinePointSize(k));
    park_deltas_bytes_ =
        std::make_unique<uint8_t[]>(CalculateMaxDeltasSize(k, 1));
    park_stubs_bytes_ = std::make_unique<uint8_t[]>(CalculateStubsSize(k));

    Timer all_phases;
#ifdef USE_HELLMAN_ATTACK
    std::cout << std::endl
              << "Starting phase 0/4: Hellman Attack, build extra metadata..."
              << std::endl;
    Timer hellman_timer;

    BuildExtraStorage("plot.dat.hellman", k, id, extra_metadata_hellman_);
    hellman_timer.PrintElapsed("Time for phase 0 =");
#endif

    std::cout << std::endl
              << "Starting phase 1/4: Forward Propagation..." << std::endl;
    Timer p1;
    WritePlotFile(k, id, memo, memo_len);
    p1.PrintElapsed("Time for phase 1 =");

    std::cout << std::endl
              << "Starting phase 2/4: Backpropagation..." << std::endl;
    Timer p2;
    Backpropagate(k);
    p2.PrintElapsed("Time for phase 2 =");

    std::cout << std::endl << "Starting phase 3/4: Compression..." << std::endl;
    Timer p3;
    Phase3Results res = CompressTables(k, id, memo, memo_len);
    p3.PrintElapsed("Time for phase 3 =");

    std::cout << std::endl
              << "Starting phase 4/4: Write Checkpoint tables..." << std::endl;
    Timer p4;
    WriteCTables(k, k + 1, res);
    p4.PrintElapsed("Time for phase 4 =");

    std::cout << std::endl
              << "Approximate working space used: "
              << static_cast<double>(tables_[8].begin) / (1_GB) << " GB"
              << std::endl;
    std::cout << "Final file size: "
              << static_cast<double>(res.final_table_begin_pointers[11]) /
                     (1_GB)
              << " GB" << std::endl;

    all_phases.PrintElapsed("Total time =");

    double vm_usage, resident_set;
    process_mem_usage(vm_usage, resident_set);
    std::cout << "Virtual memory used: " << std::fixed << std::setprecision(3)
              << vm_usage / (1_MB) << " GB" << std::endl;
    std::cout << "Physical memory used: " << std::fixed << std::setprecision(3)
              << resident_set / (1_MB) << " GB" << std::endl;

    // remove temp workspace file
    if (std::filesystem::exists(plot_filename)) {
      temp_.reset();
      std::filesystem::remove(plot_filename);
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t GetMaxEntrySize(uint8_t k, uint8_t table_index,
                                         bool phase_1_size) __attribute((hot)) {
    switch (table_index) {
    case 1:
      // Represents f1, x
      return Util::ByteAlign(k + kExtraBits + k) / 8;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
      if (phase_1_size)
        // If we are in phase 1, use the max size, with metadata.
        // Represents f, pos, offset, and metadata
        return Util::ByteAlign(k + kExtraBits + (k + 1) + kOffsetSize +
                               k * kVectorLens[table_index + 1]) /
               8;
      else
        // If we are past phase 1, we can use a smaller size, the smaller
        // between phases 2 and 3. Represents either:
        //    a:  sort_key, pos, offset        or
        //    b:  line_point, sort_key
        return Util::ByteAlign(std::max(
                   static_cast<uint32_t>(k + 1 + (k + 1) + kOffsetSize),
                   static_cast<uint32_t>(2 * k + k + 1))) /
               8;
    case 7:
    default:
      // Represents line_point, f7
      return Util::ByteAlign(3 * k) / 8;
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t GetMaxEntrySizeAll(uint8_t k) {
    std::array<uint32_t, 7> arr;
    for (uint8_t i = 1; i <= 7; i++)
      arr[i - 1] = GetMaxEntrySize(k, i, true);
    return *(std::max_element(arr.begin(), arr.end()));
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint64_t GetMaxWorkspace(uint8_t k) {
    // init space with estimate for max header len 1KB
    uint64_t space{1_KB};
    // calc max sizes for tables and spare table
    uint64_t max_entry_cnt = (((uint64_t)1) << k) + 1;
    for (auto i = 1; i <= 7; i++) {
      uint64_t max_table_size = max_entry_cnt * GetMaxEntrySize(k, i, true);
      space += max_table_size;
    }
    // allocate spare based on max entry length & count + some extra 512 MB
    uint64_t max_spare_size = 512_MB + max_entry_cnt * GetMaxEntrySizeAll(k);
    return (space + max_spare_size);
  }

  // Calculates the size of one C3 park. This will store bits for each f7
  // between two C1 checkpoints, depending on how many times that f7 is present.
  // For low values of k, we need extra space to account for the additional
  // variability.
  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t CalculateC3Size(uint8_t k) __attribute((hot)) {
    if (k < 20) {
      return floor(Util::ByteAlign(8 * kCheckpoint1Interval) / 8);
    } else {
      // TODO(alex): tighten this bound, based on formula
      return Util::ByteAlign(kC3BitsPerEntry * kCheckpoint1Interval) / 8;
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t CalculateLinePointSize(uint8_t k) __attribute((hot)) {
    return Util::ByteAlign(2 * k) / 8;
  }

  // This is the full size of the deltas section in a park. However, it will not
  // be fully filled
  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t CalculateMaxDeltasSize([[maybe_unused]] uint8_t k,
                                                uint8_t table_index)
      __attribute((hot)) {
#ifndef USE_HELLMAN_ATTACK
    if (table_index == 1) {
      return Util::ByteAlign((kEntriesPerPark - 1) * kMaxAverageDeltaTable1) /
             8;
    }
    return Util::ByteAlign((kEntriesPerPark - 1) * kMaxAverageDelta) / 8;
#else
    if (table_index == 1) {
      return Util::ByteAlign((kEntriesPerPark - 1) * kMaxAverageDeltaTable1) /
             8;
    }
    if (table_index == 2) {
      return Util::ByteAlign(
                 std::floor((kEntriesPerPark - 1) * (kMaxAverageDelta + 1))) /
             8;
    }
    return Util::ByteAlign((kEntriesPerPark - 1) * kMaxAverageDelta) / 8;
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t CalculateStubsSize(uint k) __attribute((hot)) {
    return Util::ByteAlign((kEntriesPerPark - 1) * (k - kStubMinusBits)) / 8;
  }

  /////////////////////////////////////////////////////////////////////////////
  static inline uint32_t CalculateParkSize(uint8_t k, uint8_t table_index) {
    return CalculateLinePointSize(k) + CalculateStubsSize(k) +
           CalculateMaxDeltasSize(k, table_index);
  }

private:
  /// \brief tables_ - plotter table details.
  ///
  std::vector<PlotTable> tables_;

  /// \brief sort_memory - memory used in sort operations.
  ///
  std::unique_ptr<uint8_t[]> sort_memory_;

  /// \brief encoder_ - compress algoritm.
  ///
  Encoder encoder_;

  /// \brief temp_ - temporary workspace utilized in plotter phases.
  ///
  std::unique_ptr<Disk> temp_;

  /// \brief plot_ - final plot file.
  ///
  std::unique_ptr<FileDisk> plot_;

  /// \brief xxxx_bytes - park write byte buffers.
  ///
  std::unique_ptr<uint8_t[]> first_line_point_bytes_;
  std::unique_ptr<uint8_t[]> park_deltas_bytes_;
  std::unique_ptr<uint8_t[]> park_stubs_bytes_;

#ifdef USE_HELLMAN_ATTACK
  /// \brief extra_metadata_hellman_ - hellman attack metadata.
  ///
  std::vector<uint64_t> extra_metadata_hellman_;
#endif

  // Writes the plot file header to a file
  /////////////////////////////////////////////////////////////////////////////
  inline uint32_t WriteHeader(std::ostream *os, uint8_t k, uint8_t *id,
                              uint8_t *memo, uint32_t memo_len)
      __attribute__((hot)) {
    // 19 bytes  - "Proof of Space Plot" (utf-8)
    // 32 bytes  - unique plot id
    // 1 byte    - k
    // 2 bytes   - format description length
    // x bytes   - format description
    // 2 bytes   - memo length
    // x bytes   - memo

    os->write(kHeaderText.c_str(), kHeaderText.size());
    os->write(reinterpret_cast<char *>(id), kIdLen);

    uint8_t k_buffer[1]{k};
    os->write(reinterpret_cast<char *>(k_buffer), 1);

    uint8_t size_buffer[2];
    Bits(kFormatDescription.size(), 16).ToBytes(size_buffer);
    os->write(reinterpret_cast<char *>(size_buffer), 2);
    os->write(kFormatDescription.data(), kFormatDescription.size());

    Bits(memo_len, 16).ToBytes(size_buffer);
    os->write(reinterpret_cast<char *>(size_buffer), 2);
    os->write(reinterpret_cast<char *>(memo), memo_len);

    uint8_t pointers[10 * 8]{0};
    os->write(reinterpret_cast<char *>(pointers), 10 * 8);

    uint32_t bytes_written = kHeaderText.size() + kIdLen + 1 + 2 +
                             kFormatDescription.size() + 2 + memo_len + 10 * 8;
    std::cout << "WriteHeader:: " << bytes_written << " bytes" << std::endl;
    return bytes_written;
  }

  // Phase 1: calculates 1st plot table.
  /////////////////////////////////////////////////////////////////////////////
  inline void CalculateFirstTable(uint8_t k, uint8_t *id,
                                  std::vector<uint64_t> &bucket_sizes,
                                  PlotTable &table, std::ostream *writer)
      __attribute__((hot));

  // Phase 1: forward propagation.
  /////////////////////////////////////////////////////////////////////////////
  inline void WritePlotFile(uint8_t k, uint8_t *id, uint8_t *memo,
                            uint8_t memo_len) __attribute__((hot));

  // Phase 2: back propagation.
  /////////////////////////////////////////////////////////////////////////////
  inline void Backpropagate(uint8_t k) __attribute((hot));

  // Phase 3: park writer.
  /////////////////////////////////////////////////////////////////////////////
  inline void WriteParkToFile(std::ostream *writer, uint64_t table_start,
                              uint64_t park_index, uint32_t park_size_bytes,
                              uint128_t first_line_point,
                              const std::vector<uint8_t> &park_deltas,
                              const std::vector<uint64_t> &park_stubs,
                              uint8_t k, uint8_t table_index)
      __attribute((hot));

  // Phase 3: table compression.
  /////////////////////////////////////////////////////////////////////////////
  inline Phase3Results CompressTables(uint8_t k, uint8_t *id, uint8_t *memo,
                                      uint32_t memo_len) __attribute((hot));

  // Phase 4: constructs final tables.
  inline void WriteCTables(uint8_t k, uint8_t pos_size, Phase3Results &res)
      __attribute((hot));

#ifdef USE_HELLMAN_ATTACK
  // Phase 0: constructs Hellman attack extra metadata.
  inline void BuildExtraStorage(const std::string &filename, int k, uint8_t *id,
                                std::vector<uint64_t> &extra_metadata)
      __attribute((hot));
#endif
};

#include "plotter_disk_p0.hpp"
#include "plotter_disk_p1.hpp"
#include "plotter_disk_p2.hpp"
#include "plotter_disk_p3.hpp"
#include "plotter_disk_p4.hpp"

#endif // PLOTTER_DISK_HPP_
