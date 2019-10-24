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

#ifndef BUCKET_STORE_HPP
#define BUCKET_STORE_HPP

#include "file_disk.hpp"

// Store values bucketed by their leading bits into an array-like memcache.
// The memcache stores stacks of values, one for each bucket.
// The stacks are broken into segments, where each segment has content
// all from the same bucket, and a 4 bit pointer to its previous segment.
// The most recent segment is the head segment of that bucket.
// Additionally, empty segments form a linked list: 4 bit pointers of
// empty segments point to the next empty segment in the memcache.
// Each segment has size entries_per_seg * entry_len + 4, and consists of:
// [4 bit pointer to segment id] + [entries of length entry_len]*
class BucketStore {
public:
  inline explicit BucketStore(uint8_t *mem, uint64_t mem_len,
                              uint32_t entry_len, uint32_t bits_begin,
                              uint32_t bucket_log, uint64_t entries_per_seg)
      __attribute((hot)) {
    mem_ = mem;
    mem_len_ = mem_len;
    entry_len_ = entry_len;
    bits_begin_ = bits_begin;
    bucket_log_ = bucket_log;
    entries_per_seg_ = entries_per_seg;

    for (uint64_t i = 0; i < pow(2, bucket_log); i++) {
      bucket_sizes_.push_back(0);
    }

    seg_size_ = 4 + entry_len_ * entries_per_seg;

    length_ = floor(mem_len / seg_size_);

    // Initially, all the segments are empty, store them as a linked list,
    // where a segment points to the next empty segment.
    for (uint64_t i = 0; i < length_; i++) {
      SetSegmentId(i, i + 1);
    }

    // The head of the empty segments list.
    first_empty_seg_id_ = 0;

    // Initially, all bucket lists contain no segments in it.
    for (uint64_t i = 0; i < bucket_sizes_.size(); i++) {
      bucket_head_ids_.push_back(length_);
      bucket_head_counts_.push_back(0);
    }
  }

  inline void SetSegmentId(uint64_t i, uint64_t v) __attribute((hot)) {
    Util::IntToFourBytes(mem_ + i * seg_size_, v);
  }

  inline uint64_t GetSegmentId(uint64_t i) __attribute((hot)) {
    return Util::FourBytesToInt(mem_ + i * seg_size_);
  }

  // Get the first empty position from the head segment of bucket b.
  inline uint64_t GetEntryPos(uint64_t b) __attribute((hot)) {
    return bucket_head_ids_[b] * seg_size_ + 4 +
           bucket_head_counts_[b] * entry_len_;
  }

  inline void Audit() __attribute((hot)) {
    uint64_t count = 0;
    uint64_t pos = first_empty_seg_id_;

    while (pos != length_) {
      ++count;
      pos = GetSegmentId(pos);
    }
    for (uint64_t pos2 : bucket_head_ids_) {
      while (pos2 != length_) {
        ++count;
        pos2 = GetSegmentId(pos2);
      }
    }
    assert(count == length_);
  }

  inline uint64_t NumFree() __attribute((hot)) {
    uint64_t used = GetSegmentId(first_empty_seg_id_);
    return (bucket_sizes_.size() - used) * entries_per_seg_;
  }

  inline bool IsEmpty() __attribute((hot)) {
    for (uint64_t s : bucket_sizes_) {
      if (s > 0)
        return false;
    }
    return true;
  }

  inline bool IsFull() __attribute((hot)) {
    return first_empty_seg_id_ == length_;
  }

  inline void Store(uint8_t *new_val, uint64_t new_val_len) __attribute((hot)) {
    assert(new_val_len == entry_len_);
    assert(first_empty_seg_id_ != length_);
    uint64_t b =
        Util::ExtractNum(new_val, new_val_len, bits_begin_, bucket_log_);
    bucket_sizes_[b] += 1;

    // If bucket b contains no segments, or the head segment of bucket b is
    // full, append a new segment.
    if (bucket_head_ids_[b] == length_ ||
        bucket_head_counts_[b] == entries_per_seg_) {
      uint64_t old_seg_id = bucket_head_ids_[b];
      // Set the head of the bucket b with the first empty segment (thus
      // appending a new segment to the bucket b).
      bucket_head_ids_[b] = first_empty_seg_id_;
      // Move the first empty segment to the next empty one
      // (which is linked with the first empty segment using id, since empty
      // segments form a linked list).
      first_empty_seg_id_ = GetSegmentId(first_empty_seg_id_);
      // Link the head of bucket b to the previous head (in the linked list,
      // the segment that will follow the new head will be the previous head).
      SetSegmentId(bucket_head_ids_[b], old_seg_id);
      bucket_head_counts_[b] = 0;
    }

    // Get the first empty position inside the head segment and write the entry
    // there.
    uint64_t pos = GetEntryPos(b);
    std::memcpy(mem_ + pos, new_val, entry_len_);
    bucket_head_counts_[b] += 1;
  }

  inline uint64_t MaxBucket() __attribute((hot)) {
    uint64_t max_bucket_size = bucket_sizes_[0];
    uint64_t max_index = 0;
    for (uint64_t i = 1; i < bucket_sizes_.size(); i++) {
      if (bucket_sizes_[i] > max_bucket_size) {
        max_bucket_size = bucket_sizes_[i];
        max_index = i;
      }
    }
    return max_index;
  }

  inline std::vector<uint64_t> BucketsBySize() __attribute((hot)) {
    // Lukasz Wiklendt
    // (https://stackoverflow.com/questions/1577475/c-sorting-and-keeping-track-of-indexes)
    std::vector<uint64_t> idx(bucket_sizes_.size());
    iota(idx.begin(), idx.end(), 0);
    sort(idx.begin(), idx.end(), [this](uint64_t i1, uint64_t i2) {
      return bucket_sizes_[i1] > bucket_sizes_[i2];
    });
    return idx;
  }

  // Similar to how 'Bits' class works, appends an entry to the entries list,
  // such as all entries are stored into 128-bit blocks. Bits class was avoided
  // since it consumes more time than a uint128_t array.
  void AddBucketEntry(uint8_t *big_endian_bytes, uint64_t num_bytes,
                      uint16_t size_bits, uint128_t *entries, uint64_t &cnt)
      __attribute((hot)) {
    assert(size_bits / 8 >= num_bytes);
    uint16_t extra_space = size_bits - num_bytes * 8;
    uint64_t init_cnt = cnt;
    uint16_t last_size = 0;
    while (extra_space >= 128) {
      extra_space -= 128;
      entries[cnt++] = 0;
      last_size = 128;
    }
    if (extra_space > 0) {
      entries[cnt++] = 0;
      last_size = extra_space;
    }
    for (uint64_t i = 0; i < num_bytes; i += 16) {
      uint128_t val = 0;
      uint8_t bucket_size = 0;
      for (uint64_t j = i; j < i + 16 && j < num_bytes; j++) {
        val = (val << 8) + big_endian_bytes[j];
        bucket_size += 8;
      }
      if (cnt == init_cnt || last_size == 128) {
        entries[cnt++] = val;
        last_size = bucket_size;
      } else {
        uint8_t free_space = 128 - last_size;
        if (free_space >= bucket_size) {
          entries[cnt - 1] = (entries[cnt - 1] << bucket_size) + val;
          last_size += bucket_size;
        } else {
          uint8_t suffix_size = bucket_size - free_space;
          uint128_t mask = (static_cast<uint128_t>(1)) << suffix_size;
          mask--;
          uint128_t suffix = (val & mask);
          uint128_t prefix = (val >> suffix_size);
          entries[cnt - 1] = (entries[cnt - 1] << free_space) + prefix;
          entries[cnt++] = suffix;
          last_size = suffix_size;
        }
      }
    }
  }

  // Extracts 'number_of_entries' from bucket b and empties memory of those from
  // BucketStore.
  inline uint128_t *BucketHandle(uint64_t b, uint64_t number_of_entries,
                                 uint64_t &final_size) __attribute((hot)) {
    uint32_t L = entry_len_;
    uint32_t entry_size = L / 16;
    if (L % 16)
      ++entry_size;
    uint64_t cnt = 0;
    uint64_t cnt_entries = 0;
    // Entry bytes will be compressed into uint128_t array.
    uint128_t *entries = new uint128_t[number_of_entries * entry_size];

    // As long as we have a head segment in bucket b...
    while (bucket_head_ids_[b] != length_) {
      // ...extract the entries from it.
      uint64_t start_pos = GetEntryPos(b) - L;
      uint64_t end_pos = start_pos - bucket_head_counts_[b] * L;
      for (uint64_t pos = start_pos; pos > end_pos + L; pos -= L) {
        bucket_sizes_[b] -= 1;
        bucket_head_counts_[b] -= 1;
        AddBucketEntry(mem_ + pos, L, L * 8, entries, cnt);
        ++cnt_entries;
        if (cnt_entries == number_of_entries) {
          final_size = cnt;
          return entries;
        }
      }

      // Move to the next segment from bucket b.
      uint64_t next_full_seg_id = GetSegmentId(bucket_head_ids_[b]);
      // The processed segment becomes now an empty segment.
      SetSegmentId(bucket_head_ids_[b], first_empty_seg_id_);
      first_empty_seg_id_ = bucket_head_ids_[b];
      // Change the head of bucket b.
      bucket_head_ids_[b] = next_full_seg_id;

      if (next_full_seg_id == length_) {
        bucket_head_counts_[b] = 0;
      } else {
        bucket_head_counts_[b] = entries_per_seg_;
      }

      if (start_pos != end_pos) {
        bucket_sizes_[b] -= 1;
        AddBucketEntry(mem_ + end_pos + L, L, L * 8, entries, cnt);
        ++cnt_entries;
        if (cnt_entries == number_of_entries) {
          final_size = cnt;
          return entries;
        }
      }
    }

    assert(bucket_sizes_[b] == 0);
    final_size = cnt;
    return entries;
  }

private:
  uint8_t *mem_;
  uint64_t mem_len_;
  uint32_t bits_begin_;
  uint32_t entry_len_;
  uint32_t bucket_log_;
  uint64_t entries_per_seg_;
  std::vector<uint64_t> bucket_sizes_;
  uint64_t seg_size_;
  uint64_t length_;
  uint64_t first_empty_seg_id_;
  std::vector<uint64_t> bucket_head_ids_;
  std::vector<uint64_t> bucket_head_counts_;
};

#endif // BUCKET_STORE_HPP
