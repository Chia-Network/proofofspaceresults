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

#ifndef SORTING_HPP
#define SORTING_HPP

#include "bucket_store.hpp"
#include "file_disk.hpp"
#include "memory_map.hpp"

//#define VCL_NAMESPACE vcl
//#include "vectorclass.h"

// Memory cache for sorting containing 2 blocks:
//  1. Memory block for doing the sort
//  2. StreamBuffer block to read data from disk
// NOTE:
// Not optimal solution for stream buffer, too much intermediate
// buffering:
// 1. file buffer
// 2. stream buffer
// Better solution if file/memory map would provide direct access
// pointers into file or mapped file region for sorter.
//
// Current solution can use memory map. The interface uses std::iostreams
// that uses buffers containing pointers into mapped file region. This is
// better because there is no file buffers.
//////////////////////////////////////////////////////////////////////////////

#define ENTRY_POS(mem, index, len) (mem + (index * len))

/// \brief The BufWriter class - helper to write data back to disk via buffer.
///////////////////////////////////////////////////////////////////////////////
class BufWriter {
public:
  inline explicit BufWriter(std::ostream *writer, uint8_t *buf, uint64_t len)
      : buf_{buf}, len_{len}, offset_{0}, writer_{writer} {
    std::memset(buf_, 0, len_);
  }

  inline void add_item(uint8_t *item, uint64_t item_len) {
    if (is_full(item_len))
      flush();
    m_assert(offset_ + item_len < len_, "buffer too small");
    std::memcpy(buf_ + offset_, item, item_len);
    offset_ += item_len;
  }

  inline bool is_full(uint64_t size) { return (offset_ + size >= len_); }

  inline void flush() {
    m_assert(offset_ < len_, "buffer write overflow");
    writer_->write(reinterpret_cast<char *>(buf_), offset_);
    writer_->flush();
    offset_ = 0;
  }

private:
  uint8_t *buf_;
  uint64_t len_;
  uint64_t offset_;

  std::ostream *writer_;
};

//////////////////////////////////////////////////////////////////////////////
// Aliases for sort method argument tuples
//////////////////////////////////////////////////////////////////////////////
/*
inline void QuickSort(uint8_t *memory,
uint32_t entry_len,
uint64_t
num_entries, uint32_t bits_begin)
*/
using QSort = std::tuple<uint8_t *, uint32_t, uint64_t, uint32_t>;

/*
inline void QuickSortInner(uint8_t *memory,
uint64_t memory_len,
uint32_t L,
uint32_t bits_begin,
uint64_t begin,
uint64_t end,
uint8_t *pivot_space)
*/
using QSInner = std::tuple<uint8_t *, uint64_t, uint32_t, uint32_t, uint64_t,
                           uint64_t, uint8_t *>;

/*
inline void SortInMemory(Disk &disk,
uint64_t disk_begin,
uint8_t *memory,
uint32_t entry_len,
uint64_t num_entries,
uint32_t bits_begin)
*/
using MSort = std::tuple<uint64_t, uint8_t *, uint32_t, uint64_t, uint32_t>;

/*
inline void SortOnDisk(Disk &disk,
uint64_t disk_begin,
uint64_t spare_begin,
uint32_t entry_len,
uint32_t bits_begin,
const std::vector<uint64_t>& bucket_sizes,
uint8_t *mem,
uint64_t mem_len,
int quicksort = 0)
*/
using DSort =
    std::tuple<uint64_t, uint64_t, uint32_t, uint32_t,
               const std::vector<uint64_t> &, uint8_t *, uint64_t, int>;

//////////////////////////////////////////////////////////////////////////////
// Classes
//////////////////////////////////////////////////////////////////////////////

/**
 * @brief The SortBase class - contains implementation for static helper fns.
 */
class SortBase {
public:
  virtual ~SortBase() {}

  virtual void quickSort(QSort &) = 0;
  virtual void diskSort(DSort &) = 0;
  virtual void memorySort(MSort &) = 0;

  /**
   * @brief makeParam - builds param tuple for disk sort using given arguments.
   */
  static inline DSort makeParam(uint64_t disk_begin, uint64_t spare_begin,
                                uint32_t entry_len, uint32_t bits_begin,
                                const std::vector<uint64_t> &bucket_sizes,
                                uint8_t *mem, uint64_t mem_len, int quicksort)
      __attribute((hot)) {
    DSort param =
        std::make_tuple(disk_begin, spare_begin, entry_len, bits_begin,
                        std::cref(bucket_sizes), mem, mem_len, quicksort);
    return param;
  }

  /**
   * @brief makeParam - builds param tuple for memory sort using given
   * arguments.
   */
  static inline MSort makeParam(uint64_t disk_begin, uint8_t *mem,
                                uint32_t entry_len, uint64_t num_entries,
                                uint32_t bits_begin) __attribute((hot)) {
    MSort param =
        std::make_tuple(disk_begin, mem, entry_len, num_entries, bits_begin);
    return param;
  }

  /**
   * @brief MemCmpBits - Like memcmp, but only compares starting at a certain
   * bit.
   */
  static inline int MemCmpBits(uint8_t *left_arr, uint8_t *right_arr,
                               uint32_t len, uint32_t bits_begin)
      __attribute((hot)) {
    uint32_t start_byte = bits_begin / 8;
    uint8_t mask = ((1 << (8 - (bits_begin % 8))) - 1);
    if ((left_arr[start_byte] & mask) != (right_arr[start_byte] & mask)) {
      return (left_arr[start_byte] & mask) - (right_arr[start_byte] & mask);
    }

    for (uint32_t i = start_byte + 1; i < len; i++) {
      if (left_arr[i] != right_arr[i])
        return left_arr[i] - right_arr[i];
    }
    return 0;
  }

  /**
   * @brief RoundSize - The number of memory entries required to do the custom
   * SortInMemory algorithm, given the total number of entries to be sorted.
   */
  static inline uint64_t RoundSize(uint64_t size) __attribute((hot)) {
    size *= 2;
    uint64_t result = 1;
    while (result < size)
      result *= 2;
    return result + 50;
  }

  /**
   * @brief IsPositionEmpty - Checks if given position is zero.
   */
  static inline bool IsPositionEmpty(const uint8_t *const pos,
                                     const uint64_t size) __attribute((hot)) {
#ifndef USE_BIT_FIDDLING
    return (*pos == 0 && std::memcmp(pos, pos + 1, size - 1) == 0);
#else
    uint64_t k{size};
    while (--k != 0 && pos[k] == 0)
      ;
    return (k == 0);
#endif
  }
};

/**
 * @brief The Sort class - contains implementation for sorting fns.
 */
class Sort : public SortBase {
public:
  explicit Sort(Disk *disk) : disk_(disk) {}

  ~Sort() override {}

  /**
   * @brief quickSort - runs quick sort for given arguments.
   */
  inline void quickSort(QSort &) override __attribute((hot));

  /**
   * @brief diskSort - does sort on disk using given arguments.
   */
  inline void diskSort(DSort &) override __attribute((hot));

  /**
   * @brief memorySort - does sort on memory using given arguments.
   */
  inline void memorySort(MSort &) override __attribute((hot));

  static constexpr uint64_t kSortMemorySize = 2_GB;

private:
  Disk *disk_{nullptr};
  uint8_t *disk_buf_{nullptr};
  std::unique_ptr<uint8_t[]> entry_{nullptr};
  std::unique_ptr<uint8_t[]> entry_swap_{nullptr};
  uint32_t entry_len_{0};
  std::unique_ptr<uint8_t[]> common_prefix_{nullptr};
  uint32_t common_prefix_len_{0};

  QSInner qs_inner_;
  inline void innerQuickSort() __attribute((hot));
};

//////////////////////////////////////////////////////////////////////////////
inline void Sort::quickSort(QSort &param) {
  auto [memory, entry_len, num_entries, bits_begin] = param;
#ifndef NDEBUG
  TimedSection s("\t\t* quick sort:");
#endif
  uint64_t memory_len = uint64_t(entry_len) * num_entries;
  qs_inner_ = std::make_tuple(memory, memory_len, entry_len, bits_begin, 0,
                              num_entries, entry_swap_.get());
  innerQuickSort();
}

//////////////////////////////////////////////////////////////////////////////
inline void Sort::innerQuickSort() {
  auto [memory, memory_len, len_entry, bits_begin, begin, end, pivot_space] =
      qs_inner_;

  const auto mem = memory;
  const auto entry_len = len_entry;
  auto get_entry_pos = [&entry_len, &mem](auto index) {
    return mem + (index * entry_len);
  };

  if (end - begin <= 5) {
    for (uint64_t i = begin + 1; i < end; i++) {
      uint64_t j = i;
      std::memcpy(pivot_space, get_entry_pos(i), entry_len);
      while (j > begin && MemCmpBits(get_entry_pos(j - 1), pivot_space,
                                     entry_len, bits_begin) > 0) {
        std::memcpy(get_entry_pos(j), get_entry_pos(j - 1), entry_len);
        j--;
      }
      std::memcpy(get_entry_pos(j), pivot_space, entry_len);
    }
    return;
  }

  uint64_t lo = begin;
  uint64_t hi = end - 1;

  std::memcpy(pivot_space, get_entry_pos(hi), entry_len);
  bool left_side = true;

  while (lo < hi) {
    if (left_side) {
      if (MemCmpBits(get_entry_pos(lo), pivot_space, entry_len, bits_begin) <
          0) {
        ++lo;
      } else {
        std::memcpy(get_entry_pos(hi), get_entry_pos(lo), entry_len);
        --hi;
        left_side = false;
      }
    } else {
      if (MemCmpBits(get_entry_pos(hi), pivot_space, entry_len, bits_begin) >
          0) {
        --hi;
      } else {
        std::memcpy(get_entry_pos(lo), get_entry_pos(hi), entry_len);
        ++lo;
        left_side = true;
      }
    }
  }
  std::memcpy(get_entry_pos(lo), pivot_space, entry_len);

  if (lo - begin <= end - lo) {
    qs_inner_ = std::make_tuple(mem, memory_len, entry_len, bits_begin, begin,
                                lo, pivot_space);
    innerQuickSort();
    qs_inner_ = std::make_tuple(mem, memory_len, entry_len, bits_begin, lo + 1,
                                end, pivot_space);
    innerQuickSort();
  } else {
    qs_inner_ = std::make_tuple(mem, memory_len, entry_len, bits_begin, lo + 1,
                                end, pivot_space);
    innerQuickSort();
    qs_inner_ = std::make_tuple(mem, memory_len, entry_len, bits_begin, begin,
                                lo, pivot_space);
    innerQuickSort();
  }
}

#if 0
  // XXXX:: Merge sort
  // Merges two subarrays of arr[].
  // First subarray is arr[l..m]
  // Second subarray is arr[m+1..r]
  void merge(int arr[], int l, int m, int r)
  {
      int i, j, k;
      int n1 = m - l + 1;
      int n2 =  r - m;

      /* create temp arrays */
      int L[n1], R[n2];

      /* Copy data to temp arrays L[] and R[] */
      for (i = 0; i < n1; i++)
          L[i] = arr[l + i];
      for (j = 0; j < n2; j++)
          R[j] = arr[m + 1+ j];

      /* Merge the temp arrays back into arr[l..r]*/
      i = 0; // Initial index of first subarray
      j = 0; // Initial index of second subarray
      k = l; // Initial index of merged subarray
      while (i < n1 && j < n2)
      {
          if (L[i] <= R[j])
          {
              arr[k] = L[i];
              i++;
          }
          else
          {
              arr[k] = R[j];
              j++;
          }
          k++;
      }

      /* Copy the remaining elements of L[], if there
         are any */
      while (i < n1)
      {
          arr[k] = L[i];
          i++;
          k++;
      }

      /* Copy the remaining elements of R[], if there
         are any */
      while (j < n2)
      {
          arr[k] = R[j];
          j++;
          k++;
      }
  }

  /* l is for left index and r is right index of the
     sub-array of arr to be sorted */
  void mergeSort(int arr[], int l, int r)
  {
      if (l < r)
      {
          // Same as (l+r)/2, but avoids overflow for
          // large l and h
          int m = l+(r-l)/2;

          // Sort first and second halves
          mergeSort(arr, l, m);
          mergeSort(arr, m+1, r);

          merge(arr, l, m, r);
      }
  }
#endif

//////////////////////////////////////////////////////////////////////////////
void Sort::memorySort(MSort &param) {
  auto [disk_begin, memory, entry_len, num_entries, bits_begin] = param;

#ifndef NDEBUG
  TimedSection s("\t\t* memory sort:");
#endif
  // allocate space for common prefix if necessary
  uint64_t common_prefix_len = bits_begin / 8;
  if (common_prefix_len != common_prefix_len_) {
    if (common_prefix_len > 0)
      common_prefix_ = std::make_unique<uint8_t[]>(common_prefix_len);
    common_prefix_len_ = common_prefix_len;
  }
  uint32_t plain_entry_len = entry_len - common_prefix_len;
  uint64_t memory_len = RoundSize(num_entries) * plain_entry_len;

  // sanity checks
  m_assert(plain_entry_len <= entry_len_, "invalid plain entry length");

  uint32_t bucket_length = 0;
  bool set_prefix = false;
  // The number of buckets needed (the smallest power of 2 greater than 2 *
  // num_entries).
  while ((1UL << bucket_length) < 2 * num_entries)
    bucket_length++;

  // zeroing sort memory
  uint64_t len = sizeof(uint8_t) * memory_len;
  std::memset(memory, 0, len);

  uint64_t buf_pos = 0;
  uint64_t buf_ptr = 0;

  // read loop: read entries from disk starting at pos == disk_begin
  // into disk buffer then sort entries using memory allocated for sort
  std::istream *reader = disk_->ReadHandle(disk_begin);
  uint64_t disk_buf_len = disk_->GetStreamBufferSize();
  for (uint64_t i = 0; i < num_entries; i++) {
    if (buf_pos == 0) {
      // If read buffer is empty, read from disk and refill it.
      buf_pos = std::min(disk_buf_len / entry_len, num_entries - i);
      buf_ptr = 0;
      m_assert(buf_pos * entry_len <= disk_buf_len, "disk_buf read overflow");

      reader->read(reinterpret_cast<char *>(disk_buf_), buf_pos * entry_len);
      if (set_prefix == false && common_prefix_len > 0) {
        // We don't store the common prefix of all entries in memory, instead
        // just append it every time in write buffer.
        std::memcpy(common_prefix_.get(), disk_buf_, common_prefix_len);
        set_prefix = true;
      }
    }
    buf_pos--;
    // First unique bits in the entry give the expected position of it in the
    // sorted array. We take 'bucket_length' bits starting with the first
    // unique one.
    uint64_t pos =
        plain_entry_len * Util::ExtractNum(disk_buf_ + buf_ptr, entry_len,
                                           bits_begin, bucket_length);

    const auto entry_offset = buf_ptr + common_prefix_len;
    m_assert(entry_offset + plain_entry_len <= disk_buf_len,
             "disk buffer overflow");
    // As long as position is occupied by a previous entry...
    while (IsPositionEmpty(memory + pos, plain_entry_len) == false &&
           pos < memory_len) {
      // ...store there the minimum between the two and continue to push the
      // higher one.
      if (MemCmpBits(memory + pos, disk_buf_ + entry_offset, plain_entry_len,
                     0) > 0) {
        // We always store the entry without the common prefix.
        std::swap_ranges(memory + pos, memory + pos + plain_entry_len,
                         disk_buf_ + entry_offset);
      }
      pos += plain_entry_len;
    }
    // Push the entry in the first free spot.
    std::memcpy(memory + pos, disk_buf_ + entry_offset, plain_entry_len);
    buf_ptr += entry_len;
  }

  uint64_t entries_written = 0;
  buf_pos = 0;

  // write loop: write sorted entries back to disk from memory
  // via disk buf.
  BufWriter writer(disk_->WriteHandle(disk_begin), disk_buf_, disk_buf_len);
  for (uint64_t pos = 0; entries_written < num_entries && pos < memory_len;
       pos += plain_entry_len) {
    if (IsPositionEmpty(memory + pos, plain_entry_len) == false) {
      // We've found an entry, add possible common prefix + entry data
      if (common_prefix_len > 0)
        writer.add_item(common_prefix_.get(), common_prefix_len);
      writer.add_item(memory + pos, plain_entry_len);
      entries_written++;
    }
  }
  writer.flush();

  m_assert(entries_written == num_entries, "memory sort dropped entries");
}

//////////////////////////////////////////////////////////////////////////////
void Sort::diskSort(DSort &param) {
  auto [disk_begin, spare_begin, entry_len, bits_begin, bucket_sizes, mem,
        mem_len, quicksort] = param;

  if (bits_begin >= entry_len * 8)
    return;

  // init memory (1st call disk_buf_ == NULL)
  if (disk_buf_ == nullptr) {
    disk_buf_ = mem + mem_len;
    entry_len_ = entry_len;
    entry_ = std::make_unique<uint8_t[]>(entry_len_);
    entry_swap_ = std::make_unique<uint8_t[]>(entry_len_);
  }

  // bucket_sizes[i] represent how many entries start with the prefix i (from
  // 0000 to 1111). i.e. bucket_sizes[10] represents how many entries start
  // with the prefix 1010.
  uint64_t total_size = 0;
  for (auto &n : bucket_sizes)
    total_size += n;

  if (disk_begin + (total_size * entry_len) > spare_begin) {
    uint64_t required_spare_size = (total_size * entry_len);
    uint64_t current_spare_size = spare_begin - disk_begin;
    uint64_t extra_size = required_spare_size - current_spare_size;
    std::stringstream ss;
    ss << "Sort: disk begin and spare begin overlap, required size = "
       << uint64_t{required_spare_size}
       << ", current_size = " << uint64_t{current_spare_size}
       << ", additional size needed = " << uint64_t{extra_size}
       << ", total_size = " << uint64_t{total_size}
       << ", entry_len = " << uint64_t{entry_len};
    throw std::runtime_error(ss.str().c_str());
  }

  // If we have enough memory to sort the entries, do it.
  uint64_t length = static_cast<uint64_t>(floor(mem_len / entry_len));

  // Are we in Compress phrase 1 (quicksort=1) or is it the last bucket
  // (quicksort=2)? Perform quicksort if it fits in the memory (SortInMemory
  // algorithm won't always perform well).
  if (quicksort > 0 && total_size <= length) {
    disk_->Read(disk_begin, mem, total_size * entry_len);
    QSort param = std::make_tuple(mem, entry_len, total_size, bits_begin);
    quickSort(param);
    disk_->Write(disk_begin, mem, total_size * entry_len);
    return;
  }

  // Do SortInMemory algorithm if it fits in the memory
  // (number of entries required * entry_len_memory) <= total memory available
  uint32_t plain_entry_len = entry_len - (bits_begin / 8);
  if (quicksort == 0 && RoundSize(total_size) * plain_entry_len <= mem_len) {
    MSort param = makeParam(disk_begin, mem, entry_len, total_size, bits_begin);
    memorySort(param);
    return;
  }

  {
#ifndef NDEBUG
    TimedSection s("\t\t* disk sort done:");
#endif

    std::vector<uint64_t> bucket_begins;
    bucket_begins.push_back(0);
    uint64_t total = 0;

    // The beginning of each bucket. The first entry from bucket i will always
    // be written on disk on position disk_begin + bucket_begins[i] * entry_len,
    // the second one will be written on position disk_begin + (bucket_begins[i]
    // + 1)
    // * entry_len and so on. This way, when all entries are written back to
    // disk, they will be sorted by the first 4 bits (the bucket) at the end.
    uint64_t bucket_cnt = bucket_sizes.size();
    for (uint64_t i = 0; i < bucket_cnt - 1; i++) {
      total += bucket_sizes[i];
      bucket_begins.push_back(total);
    }

    uint32_t bucket_log = Util::GetSizeBits(bucket_cnt) - 1;

    // Move the beginning of each bucket into the spare.
    uint64_t spare_written = 0;
    std::vector<uint64_t> consumed_per_bucket(bucket_cnt, 0);

    // The spare stores about 5 * N_buckets * len(mem) entries.
    uint64_t unit = static_cast<uint64_t>(
        floor(length / static_cast<double>(bucket_cnt) * 5));

    for (uint32_t i = 0; i < bucket_sizes.size(); i++) {
      uint64_t b_size = bucket_sizes[i];
      uint64_t to_consume = std::min(unit, b_size);

      while (to_consume > 0) {
        uint64_t next_amount = std::min(length, to_consume);
        uint64_t pos_rd =
            disk_begin +
            ((bucket_begins[i] + consumed_per_bucket[i]) * entry_len);

        disk_->Read(pos_rd, mem, next_amount * entry_len);
        uint64_t pos_wr = spare_begin + (spare_written * entry_len);
        disk_->Write(pos_wr, mem, next_amount * entry_len);
        to_consume -= next_amount;
        spare_written += next_amount;
        consumed_per_bucket[i] += next_amount;
      }
    }

    //////////////////////////////////////////////////////////////////////////
    // BucketStore magic start
    //////////////////////////////////////////////////////////////////////////
    std::vector<std::vector<uint64_t>> subbucket_sizes;
    {
#ifndef NDEBUG
      std::cout << "\t\tbucket store magic start..." << std::endl;
      TimedSection ts("\t\t* bucket sort:");
#endif
      // Populate BucketStore from spare.
      BucketStore bstore(mem, mem_len, entry_len, bits_begin, bucket_log, 100);
      uint64_t spare_consumed = 0;

      std::istream *reader = disk_->ReadHandle(spare_begin);
#ifndef NDEBUG
      std::cout << "\t\t...populate bucket store from spare" << std::endl;
#endif
      while (!bstore.IsFull() && spare_consumed < spare_written) {
        reader->read(reinterpret_cast<char *>(entry_.get()), entry_len);
        bstore.Store(entry_.get(), entry_len);
        spare_consumed += 1;
      }

      // subbuckets[i][j] represents how many entries starting with prefix i has
      // the next prefix equal to j. When we'll call recursively for all entries
      // starting with the prefix i, bucket_sizes[] becomes subbucket_sizes[i].
      for (uint64_t i = 0; i < bucket_cnt; i++) {
        std::vector<uint64_t> col(bucket_cnt, 0);
        subbucket_sizes.push_back(col);
      }

      std::vector<uint64_t> written_per_bucket(bucket_cnt, 0);
#ifndef NDEBUG
      std::cout << "\t\t...process bucket store" << std::endl;
#endif
      while (!bstore.IsEmpty()) {
        // Write from BucketStore the heaviest buckets first (so it empties
        // faster)
        for (uint64_t b : bstore.BucketsBySize()) {
          if (written_per_bucket[b] >= consumed_per_bucket[b]) {
            continue;
          }
          uint64_t final_size;
          // Don't extract from the bucket more entries than the difference
          // between read and written entries (this avoids overwritting entries
          // that were not read yet).
          uint128_t *bucket_handle = bstore.BucketHandle(
              b, consumed_per_bucket[b] - written_per_bucket[b], final_size);
          uint32_t entry_size = entry_len / 16;
          uint8_t last_size = (entry_len * 8) % 128;
          if (last_size == 0)
            last_size = 128;
          if (entry_len % 16)
            ++entry_size;
          // Write the content of the bucket in the right spot (beginning of the
          // bucket + number of entries already written in that bucket).
          uint64_t pos =
              disk_begin +
              ((bucket_begins[b] + written_per_bucket[b]) * entry_len);
          std::ostream *writer = disk_->WriteHandle(pos);
          for (uint64_t i = 0; i < final_size; i += entry_size) {
            Util::EntryToBytes(bucket_handle, i, i + entry_size, last_size,
                               entry_.get());
            writer->write(reinterpret_cast<char *>(entry_.get()), entry_len);
            written_per_bucket[b] += 1;
            subbucket_sizes[b][Util::ExtractNum(entry_.get(), entry_len,
                                                bits_begin + bucket_log,
                                                bucket_log)] += 1;
          }
          writer->flush();
          delete[] bucket_handle;
        }

        // Advance the read handle into buckets and move read entries to
        // BucketStore. We read first from buckets with the smallest difference
        // between read and write handles. The goal is to increase the smaller
        // differences. The bigger the difference is, the better, as in the next
        // step, we'll be able to extract more from the BucketStore.
#ifndef NDEBUG
        std::cout << "\t\t...do idx sort" << std::endl;
#endif
        std::vector<uint64_t> idx(bucket_sizes.size());
        iota(idx.begin(), idx.end(), 0);
        sort(idx.begin(), idx.end(),
             [&consumed_per_bucket, &written_per_bucket](uint64_t i1,
                                                         uint64_t i2) {
               return (consumed_per_bucket[i1] - written_per_bucket[i1] <
                       consumed_per_bucket[i2] - written_per_bucket[i2]);
             });

        bool broke = false;
        for (uint64_t i : idx) {
          if (consumed_per_bucket[i] == bucket_sizes[i]) {
            continue;
          }
          uint64_t pos =
              disk_begin +
              ((bucket_begins[i] + consumed_per_bucket[i]) * entry_len);
          reader->seekg(pos);
#ifndef NDEBUG
          std::cout << "\t\t...reprocess bucket store again" << std::endl;
#endif
          while (!bstore.IsFull() && consumed_per_bucket[i] < bucket_sizes[i]) {
            reader->read(reinterpret_cast<char *>(entry_.get()), entry_len);
            bstore.Store(entry_.get(), entry_len);
            consumed_per_bucket[i] += 1;
          }
          if (bstore.IsFull()) {
            broke = true;
            break;
          }
        }
        // If BucketStore still isn't full and we've read all entries from
        // buckets, start populating from the spare space.
        if (!broke) {
          reader->seekg(spare_begin + (spare_consumed * entry_len));
#ifndef NDEBUG
          std::cout << "\t\t...repopulate bucket store from spare" << std::endl;
#endif
          while (!bstore.IsFull() && spare_consumed < spare_written) {
            reader->read(reinterpret_cast<char *>(entry_.get()), entry_len);
            bstore.Store(entry_.get(), entry_len);
            spare_consumed += 1;
          }
        }
      }
    }
#ifndef NDEBUG
    std::cout << "\t\t...bucket store magic end" << std::endl;
#endif
    //////////////////////////////////////////////////////////////////////////
    // BucketStore magic end
    //////////////////////////////////////////////////////////////////////////

    // The last bucket that contains at least one entry.
    auto last_bucket = bucket_cnt - 1;
    while (last_bucket > 0) {
      bool all_zero = true;
      for (uint64_t i = 0; i < bucket_cnt; i++)
        if (subbucket_sizes[last_bucket][i] != 0)
          all_zero = false;
      if (!all_zero)
        break;
      last_bucket--;
    }

#ifndef NDEBUG
    std::cout << "\t\t...bucket sort for-loop start" << std::endl;
#endif
    for (uint32_t i = 0; i < bucket_sizes.size(); i++) {
      // Do we have to do quicksort for the new partition?
      int new_quicksort = 0;
      // If quicksort = 1, means all partitions must do the quicksort as their
      // final step. Preserve that for the new call.
      if (quicksort == 1) {
        new_quicksort = 1;
      } else {
        // If this is not the last bucket, we use the SortInMemoryAlgorithm
        // (new_quicksort = 0)
        // ..otherwise, do quicksort, as the last bucket isn't guaranteed to
        // have uniform distribution.
        if (i == last_bucket) {
          new_quicksort = 2;
        }
      }
      // At this point, all entries are sorted in increasing order by their
      // buckets (4 bits prefixes). We recursively sort each chunk, this time
      // starting with the next 4 bits to determine the buckets. (i.e. firstly,
      // we sort entries starting with 0000, then entries starting with 0001,
      // ..., then entries starting with 1111, at the end producing the correct
      // ordering).
      DSort param = makeParam(disk_begin + (bucket_begins[i] * entry_len),
                              spare_begin, entry_len, bits_begin + bucket_log,
                              subbucket_sizes[i], mem, mem_len, new_quicksort);
      diskSort(param);
    }
#ifndef NDEBUG
    std::cout << "\t\t...bucket sort for-loop end" << std::endl;
#endif
  }
}

#endif // SORTING_HPP
