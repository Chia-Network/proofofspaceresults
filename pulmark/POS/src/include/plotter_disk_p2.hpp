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

#ifndef PLOTTER_DISK_P2_HPP
#define PLOTTER_DISK_P2_HPP

// The purpose of backpropagate is to eliminate any dead entries
// that don't contribute to final values in f7, to minimize disk usage.
// A sort on disk is applied to each table, so that they are sorted by
// position.
/////////////////////////////////////////////////////////////////////////////
void DiskPlotter::Backpropagate(uint8_t k) {

  // An extra bit is used, since we may have more than 2^k entries in a table.
  // (After pruning, each table will have 0.8*2^k or less entries).
  const uint8_t pos_size = k + 1;

  // The table 8 is spare space that we can use for sort
  PlotTable &spare = tables_[8];

  const uint32_t max_entry_size_bytes = GetMaxEntrySizeAll(k);

  // buffers for reading and writing to disk
  // pre-allocate space for entry buffers based on max entry length
  std::unique_ptr<uint8_t[]> left_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);
  std::unique_ptr<uint8_t[]> new_left_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);
  std::unique_ptr<uint8_t[]> right_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);

  std::vector<uint64_t> bucket_sizes_pos(kNumSortBuckets, 0);

  // Iterates through each table (with a left and right pointer), starting at
  // 6 & 7.
  for (uint8_t table_index = 7; table_index > 1; --table_index) {
    Timer table_timer;
    PlotTable &left = tables_[table_index - 1];
    PlotTable &right = tables_[table_index];

    std::cout << "Backpropagating on table " << int{right.id} << std::endl;

    std::vector<uint64_t> new_bucket_sizes_pos(kNumSortBuckets, 0);
    uint16_t left_metadata_size = kVectorLens[table_index] * k;

    // The entry that we are writing (no metadata)
    uint32_t new_left_entry_size_bytes = GetMaxEntrySize(k, left.id, false);

    // The right entries which we read and write (the already have no
    // metadata, since they have been pruned in previous iteration)
    uint32_t new_right_entry_size_bytes = GetMaxEntrySize(k, right.id, false);

    m_assert(left.entry_len <= max_entry_size_bytes,
             "left entry size too small");
    m_assert(new_left_entry_size_bytes <= max_entry_size_bytes,
             "new left entry size too small");
    m_assert(new_right_entry_size_bytes <= max_entry_size_bytes,
             "new right entry size too small");

    // Doesn't sort table 7, since it's already sorted by pos6 (position into
    // table 6). The reason we sort, is so we can iterate through both tables
    // at once. For example, if we read a right entry (pos, offset) = (456,
    // 2), the next one might be (458, 19), and in the left table, we are
    // reading entries around pos 450, etc..
    // TODO: Possible to start sort already in Phase 1 async ?
    if (table_index != 7) {
      std::cout << "\tSorting table " << int{right.id} << " 0x" << std::hex
                << right.begin << std::dec << std::endl;
      right.size = new_right_entry_size_bytes * right.entry_cnt;
      spare.size = right.size;

      temp_.get()->Advise(right.begin, right.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      Timer sort_timer;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(
          right.begin, spare.begin, new_right_entry_size_bytes, 0,
          bucket_sizes_pos, sort_memory_.get(), Sort::kSortMemorySize, 0);
      sorter.diskSort(param);
      sort_timer.PrintElapsed("\tSort time:");
#ifdef USE_DROP_TABLE
      temp_.get()->Advise(spare.begin, spare.size, MADV_DONTNEED);
#endif
    }
    Timer computation_pass_timer;

    temp_.get()->Advise(left.begin, left.size, MADV_NORMAL);
    temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);

    // We will have reader and writer for left & right tables.
    std::istream *left_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Left, left.begin);
    std::ostream *left_writer =
        temp_.get()->WriteHandle(Disk::WriterId::Left, left.begin);
    std::istream *right_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Right, right.begin);
    std::ostream *right_writer =
        temp_.get()->WriteHandle(Disk::WriterId::Right, right.begin);

    // We will divide by 2, so it must be even.
    assert(kCachedPositionsSize % 2 == 0);

    // Used positions will be used to mark which posL are present in table R,
    // the rest will be pruned
    bool used_positions[kCachedPositionsSize]{false};

    bool should_read_entry = true;

    // Cache for when we read a right entry that is too far forward
    uint64_t cached_entry_sort_key = 0; // For table_index == 7, y is here
    uint64_t cached_entry_pos = 0;
    uint64_t cached_entry_offset = 0;

    // Sliding window map, from old position to new position (after pruning)
    uint64_t new_positions[kCachedPositionsSize];

    // Sort keys represent the ordering of entries, sorted by (y, pos,
    // offset), but using less bits (only k+1 instead of 2k + 9, etc.) This is
    // a map from old position to array of sort keys (one for each R entry
    // with this pos)
    Bits old_sort_keys[kReadMinusWrite][kMaxMatchesSingleEntry];
    // Map from old position to other positions that it matches with
    uint64_t old_offsets[kReadMinusWrite][kMaxMatchesSingleEntry];
    // Map from old position to count (number of times it appears)
    uint16_t old_counters[kReadMinusWrite]{0};

    bool end_of_right_table = false;
    // current pos that we are looking for in the L table
    uint64_t current_pos = 0;
    uint64_t end_of_table_pos = 0;
    // greatest position we have seen in R table
    uint64_t greatest_pos = 0;

    // Go through all right entries, and keep going since write pointer is
    // behind read pointer
    uint64_t left_entry_cnt{0};
    uint64_t right_entry_cnt{0};
    // uint64_t left_entry_counter = 0; // Total left entries written
    while (!end_of_right_table ||
           (current_pos - end_of_table_pos <= kReadMinusWrite)) {
      old_counters[current_pos % kReadMinusWrite] = 0;

      // Resets used positions after a while, so we use little memory
      if ((current_pos - kReadMinusWrite) % (kCachedPositionsSize / 2) == 0) {
        if ((current_pos - kReadMinusWrite) % kCachedPositionsSize == 0) {
          for (uint32_t i = kCachedPositionsSize / 2; i < kCachedPositionsSize;
               i++) {
            used_positions[i] = false;
          }
        } else {
          for (uint32_t i = 0; i < kCachedPositionsSize / 2; i++) {
            used_positions[i] = false;
          }
        }
      }
      // Only runs this code if we are still reading the right table, or we
      // still need to read more left table entries (current_pos <=
      // greatest_pos), otherwise, it skips to the writing of the final R
      // table entries
      if (!end_of_right_table || current_pos <= greatest_pos) {
        uint64_t entry_sort_key = 0;
        uint64_t entry_pos = 0;
        uint64_t entry_offset = 0;

        // std::cout << "while not end-of-right-table" << std::endl;
        while (!end_of_right_table) {
          if (should_read_entry) {
            // Need to read another entry at the current position
            right_reader->read(reinterpret_cast<char *>(right_entry_buf.get()),
                               new_right_entry_size_bytes);
            if (table_index == 7) {
              // This is actually y for table 7
              entry_sort_key = Util::SliceInt64FromBytes(
                  right_entry_buf.get(), new_right_entry_size_bytes, 0, k);
              entry_pos = Util::SliceInt64FromBytes(right_entry_buf.get(),
                                                    new_right_entry_size_bytes,
                                                    k, pos_size);
              entry_offset = Util::SliceInt64FromBytes(
                  right_entry_buf.get(), new_right_entry_size_bytes,
                  k + pos_size, kOffsetSize);
            } else {
              entry_pos = Util::SliceInt64FromBytes(right_entry_buf.get(),
                                                    new_right_entry_size_bytes,
                                                    0, pos_size);
              entry_offset = Util::SliceInt64FromBytes(
                  right_entry_buf.get(), new_right_entry_size_bytes, pos_size,
                  kOffsetSize);
              entry_sort_key = Util::SliceInt64FromBytes(
                  right_entry_buf.get(), new_right_entry_size_bytes,
                  pos_size + kOffsetSize, k + 1);
            }
          } else if (cached_entry_pos == current_pos) {
            // We have a cached entry at this position
            entry_sort_key = cached_entry_sort_key;
            entry_pos = cached_entry_pos;
            entry_offset = cached_entry_offset;
          } else {
            // The cached entry is at a later pos, so we don't read any more R
            // entries, read more L entries instead.
            break;
          }

          should_read_entry = true; // By default, read another entry
          if (entry_pos + entry_offset > greatest_pos) {
            // Greatest L pos that we should look for
            greatest_pos = entry_pos + entry_offset;
          }
          if (entry_sort_key == 0 && entry_pos == 0 && entry_offset == 0) {
            // Table R has ended, don't read any more (but keep writing)
            end_of_right_table = true;
            end_of_table_pos = current_pos;
            break;
          } else if (entry_pos == current_pos) {
            // The current L position is the current R entry
            // Marks the two matching entries as used (pos and pos+offset)
            used_positions[entry_pos % kCachedPositionsSize] = true;
            used_positions[(entry_pos + entry_offset) % kCachedPositionsSize] =
                true;

            uint64_t old_write_pos = entry_pos % kReadMinusWrite;
            if (table_index == 7) {
              // Stores the sort key for this R entry, which is just y (so k
              // bits)
              old_sort_keys[old_write_pos][old_counters[old_write_pos]] =
                  Bits(entry_sort_key, k);
            } else {
              // Stores the sort key for this R entry
              old_sort_keys[old_write_pos][old_counters[old_write_pos]] =
                  Bits(entry_sort_key, k + 1);
            }
            // Stores the other matching pos for this R entry (pos6 + offset)
            old_offsets[old_write_pos][old_counters[old_write_pos]] =
                entry_pos + entry_offset;
            ++old_counters[old_write_pos];
          } else {
            // Don't read any more right entries for now, because we haven't
            // caught up on the left table yet
            should_read_entry = false;
            cached_entry_sort_key = entry_sort_key;
            cached_entry_pos = entry_pos;
            cached_entry_offset = entry_offset;
            break;
          }
        }
        // Reads a left entry
        left_reader->read(reinterpret_cast<char *>(left_entry_buf.get()),
                          left.entry_len);

        // If this left entry is used, we rewrite it. If it's not used, we
        // ignore it.
        if (used_positions[current_pos % kCachedPositionsSize]) {
          uint64_t entry_y = Util::SliceInt64FromBytes(
              left_entry_buf.get(), left.entry_len, 0, k + kExtraBits);
          uint64_t entry_metadata(0);

          if (table_index > 2) {
            // For tables 2-6, the entry is: f, pos, offset, metadata
            entry_pos = Util::SliceInt64FromBytes(
                left_entry_buf.get(), left.entry_len, k + kExtraBits, pos_size);
            entry_offset = Util::SliceInt64FromBytes(
                left_entry_buf.get(), left.entry_len, k + kExtraBits + pos_size,
                kOffsetSize);
          } else {
            // For table1, the entry is: f, metadata
            entry_metadata =
                Util::SliceInt128FromBytes(left_entry_buf.get(), left.entry_len,
                                           k + kExtraBits, left_metadata_size);
          }
          Bits new_left_entry;
          if (table_index > 2) {
            // The new left entry is slightly different. Metadata is dropped,
            // to save space, and the counter of the entry is written
            // (sort_key). We use this instead of (y + pos + offset) since its
            // smaller.
            new_left_entry += Bits(entry_pos, pos_size);
            new_left_entry += Bits(entry_offset, kOffsetSize);
            new_left_entry += Bits(left_entry_cnt, k + 1);

            // If we are not taking up all the bits, make sure they are zeroed
            if (Util::ByteAlign(new_left_entry.GetSize()) <
                new_left_entry_size_bytes * 8) {
              std::memset(new_left_entry_buf.get(), 0,
                          new_left_entry_size_bytes);
            }
          } else {
            // For table one entries, we don't care about sort key, only y and
            // x.
            new_left_entry += Bits(entry_y, k + kExtraBits);
            new_left_entry += Bits(entry_metadata, left_metadata_size);
            // std::cout << "Writing X:" << entry_metadata.GetValue() <<
            // std::endl;
          }
          new_left_entry.ToBytes(new_left_entry_buf.get());
          left_writer->write(reinterpret_cast<char *>(new_left_entry_buf.get()),
                             new_left_entry_size_bytes);

          new_bucket_sizes_pos[Util::ExtractNum(new_left_entry_buf.get(),
                                                new_left_entry_size_bytes, 0,
                                                kSortBucketsLog)] += 1;
          // Mapped positions, so we can rewrite the R entry properly
          new_positions[current_pos % kCachedPositionsSize] = left_entry_cnt;

          // Counter for new left entries written
          left_entry_cnt++;
        }
      }
      // Write pointer lags behind the read pointer
      int64_t write_pointer_pos = current_pos - kReadMinusWrite + 1;

      // Only write entries for write_pointer_pos, if we are above 0, and
      // there are actually R entries for that pos.
      if (write_pointer_pos >= 0 &&
          used_positions[write_pointer_pos % kCachedPositionsSize]) {
        uint64_t new_pos =
            new_positions[write_pointer_pos % kCachedPositionsSize];
        Bits new_pos_bin(new_pos, pos_size);
        // There may be multiple R entries that share the write_pointer_pos,
        // so write all of them
        for (uint32_t counter = 0;
             counter < old_counters[write_pointer_pos % kReadMinusWrite];
             counter++) {
          // Creates and writes the new right entry, with the cached data
          uint64_t new_offset_pos =
              new_positions[old_offsets[write_pointer_pos % kReadMinusWrite]
                                       [counter] %
                            kCachedPositionsSize];

          Bits &new_right_entry =
              old_sort_keys[write_pointer_pos % kReadMinusWrite][counter];
          new_right_entry += new_pos_bin;
          // match_positions.push_back(std::make_pair(new_pos,
          // new_offset_pos));
          new_right_entry.AppendValue(new_offset_pos - new_pos, kOffsetSize);
          if (Util::ByteAlign(new_right_entry.GetSize()) <
              new_right_entry_size_bytes * 8) {
            std::memset(right_entry_buf.get(), 0, new_right_entry_size_bytes);
          }
          new_right_entry.ToBytes(right_entry_buf.get());
          right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                              new_right_entry_size_bytes);
          right_entry_cnt++;
        }
      }
      ++current_pos;
    }

    // write table terminating zeroes
    Bits(0, new_right_entry_size_bytes * 8).ToBytes(right_entry_buf.get());
    right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                        new_right_entry_size_bytes);
    right_entry_cnt++;
    Bits(0, new_left_entry_size_bytes * 8).ToBytes(new_left_entry_buf.get());
    left_writer->write(reinterpret_cast<char *>(new_left_entry_buf.get()),
                       new_left_entry_size_bytes);
    left_entry_cnt++;

    left_writer->flush();
    right_writer->flush();

    // calc final L/R table stats
    left.entry_len = new_left_entry_size_bytes;
    left.entry_cnt = left_entry_cnt;
    left.size = left.entry_len * left.entry_cnt;

    right.entry_len = new_right_entry_size_bytes;
    right.entry_cnt = right_entry_cnt;
    right.size = right.entry_len * right.entry_cnt;

#ifdef USE_DROP_TABLE
    // drop right table
    temp_.get()->Advise(right.begin, right.size, MADV_DONTNEED);
#endif

    bucket_sizes_pos = new_bucket_sizes_pos;

    std::cout << "\tTable " << int{left.id} << " wrote " << left_entry_cnt
              << " entries" << std::endl;
    computation_pass_timer.PrintElapsed("\tComputation pass time:");
    table_timer.PrintElapsed("Total backpropagation time::");
  }

#ifndef NDEBUG
  std::cout << "\nPlot tables (begin, entry-len, entry-count, size): "
            << std::endl;
  for (uint8_t i = 1; i <= 8; i++) {
    std::cout << tables_[i];
  }
#endif
}

#endif // PLOTTER_DISK_P2_HPP
