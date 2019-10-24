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

#ifndef PLOTTER_DISK_P3_HPP
#define PLOTTER_DISK_P3_HPP

// This writes a number of entries into a file, in the final, optimized
// format. The park contains a checkpoint value (whicch is a 2k bits line
// point), as well as EPP (entries per park) entries. These entries are each
// divded into stub and delta section. The stub bits are encoded as is, but
// the delta bits are optimized into a variable encoding scheme. Since we have
// many entries in each park, we can approximate how much space each park with
// take. Format is: [2k bits of first_line_point]  [EPP-1 stubs] [Deltas size]
// [EPP-1 deltas]....  [first_line_point] ...
/////////////////////////////////////////////////////////////////////////////
void DiskPlotter::WriteParkToFile(std::ostream *writer, uint64_t table_start,
                                  uint64_t park_index, uint32_t park_size_bytes,
                                  uint128_t first_line_point,
                                  const std::vector<uint8_t> &park_deltas,
                                  const std::vector<uint64_t> &park_stubs,
                                  uint8_t k, uint8_t table_index) {

  // Parks are fixed size, so we know where to start writing. The deltas will
  // not go over into the next park.
  writer->seekp(table_start + park_index * park_size_bytes);
  Bits first_line_point_bits(first_line_point, 2 * k);
  std::memset(first_line_point_bytes_.get(), 0, CalculateLinePointSize(k));
  first_line_point_bits.ToBytes(first_line_point_bytes_.get());
  writer->write((const char *)first_line_point_bytes_.get(),
                CalculateLinePointSize(k));

  // We use ParkBits insted of Bits since it allows storing more data
  ParkBits park_stubs_bits;
  for (uint64_t stub : park_stubs) {
    park_stubs_bits.AppendValue(stub, (k - kStubMinusBits));
  }
  uint32_t stubs_size = CalculateStubsSize(k);
  std::memset(park_stubs_bytes_.get(), 0, stubs_size);
  park_stubs_bits.ToBytes(park_stubs_bytes_.get());
  writer->write((const char *)park_stubs_bytes_.get(), stubs_size);

  // The stubs are random so they don't need encoding. But deltas are more
  // likely to be small, so we can compress them
  double R = kRValues[table_index - 1];
  // ParkBits deltas_bits = Encoding::ANSEncodeDeltas(park_deltas, R);
  ParkBits deltas_bits = encoder_.ANSEncodeDeltas(park_deltas, R);
  deltas_bits.ToBytes(park_deltas_bytes_.get());

  uint16_t encoded_size = deltas_bits.GetSize() / 8;
  assert((uint32_t)(encoded_size + 2) < CalculateMaxDeltasSize(k, table_index));
  writer->write((const char *)&encoded_size, 2);
  writer->write((const char *)park_deltas_bytes_.get(), encoded_size);
}

// Compresses the plot file tables into the final file. In order to do this,
// entries must be reorganized from the (pos, offset) bucket sorting order, to
// a more free line_point sorting order. In (pos, offset ordering), we store
// two pointers two the previous table, (x, y) which are very close together,
// by storing  (x, y-x), or (pos, offset), which can be done in about k + 8
// bits, since y is in the next bucket as x. In order to decrease this, We
// store the actual entries from the previous table (e1, e2), instead of pos,
// offset pointers, and sort the entire table by (e1,e2). Then, the deltas
// between each (e1, e2) can be stored, which require around k bits.

// Converting into this format requires a few passes and sorts on disk. It
// also assumes that the backpropagation step happened, so there will be no
// more dropped entries. See the design document for more details on the
// algorithm.
/////////////////////////////////////////////////////////////////////////////
#ifndef USE_HELLMAN_ATTACK
Phase3Results DiskPlotter::CompressTables(uint8_t k, uint8_t *id, uint8_t *memo,
                                          uint32_t memo_len) {
  // In this phase we open a new file, where the final contents of the plot
  // will be stored.
  plot_.get()->Open();
  std::ostream *plot_writer = plot_.get()->WriteHandle();

  uint32_t header_size = WriteHeader(plot_writer, k, id, memo, memo_len);

  uint8_t pos_size = k + 1;

  std::vector<uint64_t> final_table_begin_pointers(12, 0);
  final_table_begin_pointers[1] = header_size;

  plot_writer->seekp(header_size - 10 * 8);
  uint8_t table_1_pointer_bytes[8 * 8];
  Bits(final_table_begin_pointers[1], 8 * 8).ToBytes(table_1_pointer_bytes);
  plot_writer->write((const char *)table_1_pointer_bytes, 8);
  plot_writer->flush();

  PlotTable &spare = tables_[8];

  uint64_t final_entries_written = 0;

  const uint32_t max_entry_size_bytes = GetMaxEntrySizeAll(k);

  std::unique_ptr<uint8_t[]> right_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);
  std::unique_ptr<uint8_t[]> left_entry_disk_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);

  // Iterates through all tables, starting at 1, with L and R pointers.
  // For each table, R entries are rewritten with line points. Then, the right
  // table is sorted by line_point. After this, the right table entries are
  // rewritten as (sort_key, new_pos), where new_pos is the position in the
  // table, where it's sorted by line_point, and the line_points are written
  // to disk to a final table. Finally, table_i is sorted by sort_key. This
  // allows us to compare to the next table.
  for (uint8_t table_index = 1; table_index < 7; table_index++) {
    Timer table_timer;
    Timer computation_pass_1_timer;
    PlotTable &left = tables_[table_index];
    PlotTable &right = tables_[table_index + 1];

    std::cout << "Compressing tables " << int{left.id} << " and "
              << int{right.id} << std::endl;

    left.entry_len = GetMaxEntrySize(k, left.id, false);
    left.size = left.entry_len * left.entry_cnt;
    right.entry_len = GetMaxEntrySize(k, right.id, false);
    right.size = right.entry_len * right.entry_cnt;

    std::istream *left_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Left, 0);
    std::istream *right_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Right, 0);
    std::ostream *right_writer =
        temp_.get()->WriteHandle(Disk::WriterId::Right, 0);

    // The park size must be constant, for simplicity, but must be big enough
    // to store EPP entries. entry deltas are encoded with variable length,
    // and thus there is no guarantee that they won't override into the next
    // park. It is only different (larger) for table 1
    uint32_t park_size_bytes = CalculateParkSize(k, left.id);
    std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);
    uint32_t left_y_size = k + kExtraBits;

    // Sort key for table 7 is just y, which is k bits. For all other tables
    // it can be higher than 2^k and therefore k+1 bits are used.
    uint32_t right_sort_key_size = (left.id == 6 ? k : k + 1);

    temp_.get()->Advise(left.begin, left.size, MADV_NORMAL);
    temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);

    left_reader->seekg(left.begin);
    right_reader->seekg(right.begin);
    right_writer->seekp(right.begin);

    bool should_read_entry = true;
    std::vector<uint64_t> left_new_pos(kCachedPositionsSize);

    Bits old_sort_keys[kReadMinusWrite][kMaxMatchesSingleEntry];
    uint64_t old_offsets[kReadMinusWrite][kMaxMatchesSingleEntry];
    uint16_t old_counters[kReadMinusWrite];
    for (uint32_t i = 0; i < kReadMinusWrite; i++) {
      old_counters[i] = 0;
    }
    bool end_of_right_table = false;
    uint64_t current_pos = 0;
    uint64_t end_of_table_pos = 0;
    uint64_t greatest_pos = 0;

    uint64_t entry_sort_key{0}, entry_pos{0}, entry_offset{0};
    uint64_t cached_entry_sort_key = 0;
    uint64_t cached_entry_pos = 0;
    uint64_t cached_entry_offset = 0;

    // Similar algorithm as Backprop, to read both L and R tables
    // simultaneously
    right.entry_cnt = 0;
    while (!end_of_right_table ||
           (current_pos - end_of_table_pos <= kReadMinusWrite)) {
      old_counters[current_pos % kReadMinusWrite] = 0;

      if (end_of_right_table || current_pos <= greatest_pos) {
        while (!end_of_right_table) {
          if (should_read_entry) {
            // The right entries are in the format from backprop, (sort_key,
            // pos, offset)
            right_reader->read(reinterpret_cast<char *>(right_entry_buf.get()),
                               right.entry_len);
            entry_sort_key = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len, 0, right_sort_key_size);
            entry_pos = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len, right_sort_key_size,
                pos_size);
            entry_offset = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len,
                right_sort_key_size + pos_size, kOffsetSize);
          } else if (cached_entry_pos == current_pos) {
            entry_sort_key = cached_entry_sort_key;
            entry_pos = cached_entry_pos;
            entry_offset = cached_entry_offset;
          } else {
            break;
          }

          should_read_entry = true;

          if (entry_pos + entry_offset > greatest_pos) {
            greatest_pos = entry_pos + entry_offset;
          }
          if (entry_sort_key == 0 && entry_pos == 0 && entry_offset == 0) {
            end_of_right_table = true;
            end_of_table_pos = current_pos;
            break;
          } else if (entry_pos == current_pos) {
            uint64_t old_write_pos = entry_pos % kReadMinusWrite;
            old_sort_keys[old_write_pos][old_counters[old_write_pos]] =
                Bits(entry_sort_key, right_sort_key_size);
            old_offsets[old_write_pos][old_counters[old_write_pos]] =
                (entry_pos + entry_offset);
            ++old_counters[old_write_pos];
          } else {
            should_read_entry = false;
            cached_entry_sort_key = entry_sort_key;
            cached_entry_pos = entry_pos;
            cached_entry_offset = entry_offset;
            break;
          }
        }
        // The left entries are in the new format: (sort_key, new_pos), except
        // for table 1: (y, x).
        left_reader->read(reinterpret_cast<char *>(left_entry_disk_buf.get()),
                          left.entry_len);
        // We read the "new_pos" from the L table, which for table 1 is just
        // x. For other tables, the new_pos
        if (left.id == 1) {
          // Only k bits, since this is x
          left_new_pos[current_pos % kCachedPositionsSize] =
              Util::SliceInt64FromBytes(left_entry_disk_buf.get(),
                                        left.entry_len, left_y_size, k);
        } else {
          // k+1 bits in case it overflows
          left_new_pos[current_pos % kCachedPositionsSize] =
              Util::SliceInt64FromBytes(left_entry_disk_buf.get(),
                                        left.entry_len, k + 1, pos_size);
        }
      }

      uint64_t write_pointer_pos = current_pos - kReadMinusWrite + 1;

      // Rewrites each right entry as (line_point, sort_key)
      if (current_pos + 1 >= kReadMinusWrite) {
        uint64_t left_new_pos_1 =
            left_new_pos[write_pointer_pos % kCachedPositionsSize];
        for (uint32_t counter = 0;
             counter < old_counters[write_pointer_pos % kReadMinusWrite];
             counter++) {
          uint64_t left_new_pos_2 =
              left_new_pos[old_offsets[write_pointer_pos % kReadMinusWrite]
                                      [counter] %
                           kCachedPositionsSize];

          // A line point is an encoding of two k bit values into one 2k bit
          // value. uint128_t line_point =
          uint128_t line_point =
              encoder_.SquareToLinePoint(left_new_pos_1, left_new_pos_2);

          if (left_new_pos_1 > ((uint64_t)1 << k) ||
              left_new_pos_2 > ((uint64_t)1 << k)) {
            std::cout << "left or right positions too large " << std::endl;
            std::cout << (line_point > ((uint128_t)1 << (2 * k)));
            if ((line_point > ((uint128_t)1 << (2 * k)))) {
              std::cout << "L, R: " << left_new_pos_1 << " " << left_new_pos_2
                        << std::endl;
              std::cout << "Line point: " << line_point << std::endl;
              throw std::runtime_error(
                  "Compress line point calc error: line point overflow");
            }
          }
          Bits to_write = Bits(line_point, 2 * k);
          to_write +=
              old_sort_keys[write_pointer_pos % kReadMinusWrite][counter];

          m_assert(to_write.GetSize() <= right.entry_len * 8,
                   "right buffer overflow");
          to_write.ToBytes(right_entry_buf.get());
          right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                              right.entry_len);
          right.entry_cnt++;
          bucket_sizes[Util::ExtractNum(right_entry_buf.get(), right.entry_len,
                                        0, kSortBucketsLog)] += 1;
        }
      }
      current_pos += 1;
    }
    // left table not needed anymore so remove it
    temp_.get()->Advise(left.begin, left.size, MADV_REMOVE);

    // add EOT zeroes
    std::memset(right_entry_buf.get(), 0, right.entry_len);
    right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                        right.entry_len);
    right.entry_cnt++;
    right_writer->flush();

    computation_pass_1_timer.PrintElapsed("\tFirst computation pass time:");

    // update right table size before sort
    right.size = right.entry_cnt * right.entry_len;
    {
      spare.size = right.size;
      temp_.get()->Advise(right.begin, right.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      std::cout << "\tSorting table " << int{right.id} << " 0x" << std::hex
                << right.begin << std::dec << std::endl;
      Timer sort_timer;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(right.begin, spare.begin, right.entry_len,
                                    0, bucket_sizes, sort_memory_.get(),
                                    Sort::kSortMemorySize, 1);
      sorter.diskSort(param);
      sort_timer.PrintElapsed("\tSort time:");
#ifdef USE_DROP_TABLE
      temp_.get()->Advise(spare.begin, spare.size, MADV_DONTNEED);
#endif
      temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);
    }

    Timer computation_pass_2_timer;
    right_reader->seekg(right.begin);
    right_writer->seekp(right.begin);

    plot_writer->seekp(final_table_begin_pointers[table_index]);
    final_entries_written = 0;

    std::vector<uint64_t> new_bucket_sizes(kNumSortBuckets, 0);
    std::vector<uint8_t> park_deltas;
    std::vector<uint64_t> park_stubs;
    uint128_t checkpoint_line_point = 0;
    uint128_t last_line_point = 0;
    uint64_t park_index = 0;

    uint64_t total_r_entries = 0;
    for (auto x : bucket_sizes) {
      total_r_entries += x;
    }
    // Now we will write on of the final tables, since we have a table sorted
    // by line point. The final table will simply store the deltas between
    // each line_point, in fixed space groups(parks), with a checkpoint in
    // each group.
    // Bits right_entry_bits;
    right.entry_cnt = total_r_entries;
    right.size = right.entry_cnt * right.entry_len;
    for (uint64_t index = 0; index < total_r_entries; index++) {
      right_reader->read(reinterpret_cast<char *>(right_entry_buf.get()),
                         right.entry_len);
      // Right entry is read as (line_point, sort_key)
      uint128_t line_point = Util::SliceInt128FromBytes(
          right_entry_buf.get(), right.entry_len, 0, 2 * k);
      uint64_t sort_key = Util::SliceInt64FromBytes(
          right_entry_buf.get(), right.entry_len, 2 * k, right_sort_key_size);

      // Write the new position (index) and the sort key
      Bits to_write = Bits(sort_key, right_sort_key_size);
      to_write += Bits(index, k + 1);
      std::memset(right_entry_buf.get(), 0, right.entry_len);
      m_assert(to_write.GetSize() <= right.entry_len * 8,
               "final table write: right buffer overflow");
      to_write.ToBytes(right_entry_buf.get());
      right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                          right.entry_len);

      new_bucket_sizes[Util::ExtractNum(right_entry_buf.get(), right.entry_len,
                                        0, kSortBucketsLog)] += 1;
      // Every EPP entries, writes a park
      if (index % kEntriesPerPark == 0) {
        if (index != 0) {
          WriteParkToFile(plot_writer, final_table_begin_pointers[left.id],
                          park_index, park_size_bytes, checkpoint_line_point,
                          park_deltas, park_stubs, k, left.id);
          park_index += 1;
          final_entries_written += (park_stubs.size() + 1);
        }
        park_deltas.clear();
        park_stubs.clear();

        checkpoint_line_point = line_point;
      }
      uint128_t big_delta = line_point - last_line_point;

      // Since we have approx 2^k line_points between 0 and 2^2k, the average
      // space between them when sorted, is k bits. Much more efficient than
      // storing each line point. This is diveded into the stub and delta. The
      // stub is the least significant (k-kMinusStubs) bits, and largely
      // random/incompressible. The small delta is the rest, which can be
      // efficiently encoded since it's usually very small.

      uint64_t stub =
          big_delta % (((uint128_t)1) << (uint128_t)(k - kStubMinusBits));
      uint64_t small_delta = (big_delta - stub) >> (k - kStubMinusBits);

      assert(small_delta < 256);

      if ((index % kEntriesPerPark != 0)) {
        park_deltas.push_back(small_delta);
        park_stubs.push_back(stub);
      }
      last_line_point = line_point;
    }
    right_writer->flush();

    if (park_deltas.size() > 0) {
      // Since we don't have a perfect multiple of EPP entries, this writes
      // the last ones
      WriteParkToFile(plot_writer, final_table_begin_pointers[left.id],
                      park_index, park_size_bytes, checkpoint_line_point,
                      park_deltas, park_stubs, k, left.id);
      final_entries_written += (park_stubs.size() + 1);
    }
    plot_writer->flush();

    std::cout << "\tWrote " << final_entries_written << " entries" << std::endl;
    final_table_begin_pointers[table_index + 1] =
        final_table_begin_pointers[table_index] +
        (park_index + 1) * park_size_bytes;

    plot_writer->seekp(header_size - 8 * (10 - table_index));
    uint8_t table_pointer_bytes[8 * 8];
    Bits(final_table_begin_pointers[table_index + 1], 8 * 8)
        .ToBytes(table_pointer_bytes);
    plot_writer->write(reinterpret_cast<char *>(table_pointer_bytes), 8);
    plot_writer->flush();
    computation_pass_2_timer.PrintElapsed("\tSecond computation pass time:");

    {
      spare.size = right.size;
      temp_.get()->Advise(right.begin, right.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      /* This sort is needed so that in the next iteration, we can iterate
       * through both tables at ones.Note that sort_key represents y ordering,
       * and the pos, offset coordinates from forward / backprop represent
       * positions in y ordered tables. */
      std::cout << "\tRe-Sorting table " << int{right.id} << " 0x" << std::hex
                << right.begin << std::dec << std::endl;
      Timer sort_timer_2;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(right.begin, spare.begin, right.entry_len,
                                    0, new_bucket_sizes, sort_memory_.get(),
                                    Sort::kSortMemorySize, 0);
      sorter.diskSort(param);
      sort_timer_2.PrintElapsed("\tSort time:");
#ifdef USE_DROP_TABLE
      temp_.get()->Advise(spare.begin, spare.size, MADV_DONTNEED);
#endif
      temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);
    }

    table_timer.PrintElapsed("Total compress table time:");
  }

  // remove spare, there should be only table 7 available
  temp_.get()->Advise(spare.begin, spare.size, MADV_REMOVE);

#ifndef NDEBUG
  std::cout << "\nPlot tables (begin, entry-len, entry-count, size): "
            << std::endl;
  for (uint8_t i = 1; i <= 8; i++) {
    std::cout << tables_[i];
  }
#endif

  // These results will be used to write table P7 and the checkpoint tables in
  // phase 4.
  return Phase3Results{final_table_begin_pointers, final_entries_written,
                       tables_[7].entry_len * 8, header_size};
}
#else
Phase3Results DiskPlotter::CompressTables(uint8_t k, uint8_t *id, uint8_t *memo,
                                          uint32_t memo_len) {
  // In this phase we open a new file, where the final contents of the plot
  // will be stored.
  plot_.get()->Open();
  std::ostream *plot_writer = plot_.get()->WriteHandle();

  uint32_t header_size = WriteHeader(plot_writer, k, id, memo, memo_len);

  uint8_t pos_size = k + 1;
  uint32_t left_y_size = k + kExtraBits;

  std::vector<uint64_t> final_table_begin_pointers(12, 0);
  final_table_begin_pointers[1] = header_size;

  plot_writer->seekp(header_size - 10 * 8);
  uint8_t table_1_pointer_bytes[8 * 8];
  Bits(final_table_begin_pointers[1], 8 * 8).ToBytes(table_1_pointer_bytes);
  plot_writer->write((const char *)table_1_pointer_bytes, 8);
  plot_writer->flush();

  PlotTable &spare = tables_[8];

  const uint32_t max_entry_size_bytes = GetMaxEntrySizeAll(k);

  std::unique_ptr<uint8_t[]> right_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);
  std::unique_ptr<uint8_t[]> left_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_size_bytes);

  uint64_t final_entries_written = 0;
  F1Calculator f1(k, id);
  f1.ReloadKey();
  for (uint8_t table_index = 1; table_index < 7; table_index++) {
    Timer table_timer;
    Timer computation_pass_1_timer;
    PlotTable &left = tables_[table_index];
    PlotTable &right = tables_[table_index + 1];

    left.entry_len = GetMaxEntrySize(k, left.id, false);
    left.size = left.entry_len * left.entry_cnt;
    right.entry_len = GetMaxEntrySize(k, right.id, false);
    right.size = right.entry_len * right.entry_cnt;

    std::cout << "Compressing tables " << int{left.id} << " and "
              << int{right.id} << std::endl;

    // The park size must be constant, for simplicity, but must be big enough
    // to store EPP entries. entry deltas are encoded with variable length,
    // and thus there is no guarantee that they won't override into the next
    // park. It is only different (larger) for table 1
    uint32_t park_size_bytes = CalculateParkSize(k, left.id);
    std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);

    // Sort key for table 7 is just y, which is k bits. For all other tables
    // it can be higher than 2^k and therefore k+1 bits are used.
    uint32_t right_sort_key_size = (left.id == 6 ? k : k + 1);

    Bits old_sort_keys[kReadMinusWrite][kMaxMatchesSingleEntry];
    uint64_t old_offsets[kReadMinusWrite][kMaxMatchesSingleEntry];
    uint16_t old_counters[kReadMinusWrite];
    for (uint32_t i = 0; i < kReadMinusWrite; i++) {
      old_counters[i] = 0;
    }
    bool end_of_right_table = false;
    uint64_t current_pos = 0;
    uint64_t end_of_table_pos = 0;
    uint64_t greatest_pos = 0;

    uint64_t entry_sort_key{0}, entry_pos{0}, entry_offset{0};
    uint64_t cached_entry_sort_key = 0;
    uint64_t cached_entry_pos = 0;
    uint64_t cached_entry_offset = 0;

    temp_.get()->Advise(left.begin, left.size, MADV_NORMAL);
    temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);

    std::istream *left_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Left, 0);
    std::istream *right_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Right, 0);
    std::ostream *right_writer =
        temp_.get()->WriteHandle(Disk::WriterId::Right, 0);

    left_reader->seekg(left.begin);
    right_reader->seekg(right.begin);
    right_writer->seekp(right.begin);

    bool should_read_entry = true;
    std::vector<uint64_t> left_new_pos(kCachedPositionsSize);

    // Similar algorithm as Backprop, to read both L and R tables
    // simultaneously
    right.entry_cnt = 0;
    while (!end_of_right_table ||
           (current_pos - end_of_table_pos <= kReadMinusWrite)) {
      old_counters[current_pos % kReadMinusWrite] = 0;

      if (end_of_right_table || current_pos <= greatest_pos) {
        while (!end_of_right_table) {
          if (should_read_entry) {
            // The right entries are in the format from backprop, (sort_key,
            // pos, offset)
            right_reader->read(reinterpret_cast<char *>(right_entry_buf.get()),
                               right.entry_len);
            entry_sort_key = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len, 0, right_sort_key_size);
            entry_pos = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len, right_sort_key_size,
                pos_size);
            entry_offset = Util::SliceInt64FromBytes(
                right_entry_buf.get(), right.entry_len,
                right_sort_key_size + pos_size, kOffsetSize);
          } else if (cached_entry_pos == current_pos) {
            entry_sort_key = cached_entry_sort_key;
            entry_pos = cached_entry_pos;
            entry_offset = cached_entry_offset;
          } else {
            break;
          }

          should_read_entry = true;

          if (entry_pos + entry_offset > greatest_pos) {
            greatest_pos = entry_pos + entry_offset;
          }
          if (entry_sort_key == 0 && entry_pos == 0 && entry_offset == 0) {
            end_of_right_table = true;
            end_of_table_pos = current_pos;
            break;
          } else if (entry_pos == current_pos) {
            uint64_t old_write_pos = entry_pos % kReadMinusWrite;
            old_sort_keys[old_write_pos][old_counters[old_write_pos]] =
                Bits(entry_sort_key, right_sort_key_size);
            old_offsets[old_write_pos][old_counters[old_write_pos]] =
                (entry_pos + entry_offset);
            ++old_counters[old_write_pos];
          } else {
            should_read_entry = false;
            cached_entry_sort_key = entry_sort_key;
            cached_entry_pos = entry_pos;
            cached_entry_offset = entry_offset;
            break;
          }
        }
        // The left entries are in the new format: (sort_key, new_pos), except
        // for table 1: (y, x).
        left_reader->read(reinterpret_cast<char *>(left_entry_buf.get()),
                          left.entry_len);
        // We read the "new_pos" from the L table, which for table 1 is just
        // x. For other tables, the new_pos
        if (left.id == 1) {
          // Only k bits, since this is x
          left_new_pos[current_pos % kCachedPositionsSize] =
              Util::SliceInt64FromBytes(left_entry_buf.get(), left.entry_len,
                                        left_y_size, k);
        } else if (left.id == 2) {
          left_new_pos[current_pos % kCachedPositionsSize] =
              Util::SliceInt64FromBytes(left_entry_buf.get(), left.entry_len,
                                        k + 1, k);
        } else {
          // k+1 bits in case it overflows
          left_new_pos[current_pos % kCachedPositionsSize] =
              Util::SliceInt64FromBytes(left_entry_buf.get(), left.entry_len,
                                        k + 1, pos_size);
        }
      }
      uint64_t write_pointer_pos = current_pos - kReadMinusWrite + 1;

      // Rewrites each right entry as (line_point, sort_key)
      if (current_pos + 1 >= kReadMinusWrite) {
        uint64_t left_new_pos_1 =
            left_new_pos[write_pointer_pos % kCachedPositionsSize];
        for (uint32_t counter = 0;
             counter < old_counters[write_pointer_pos % kReadMinusWrite];
             counter++) {
          uint64_t left_new_pos_2 =
              left_new_pos[old_offsets[write_pointer_pos % kReadMinusWrite]
                                      [counter] %
                           kCachedPositionsSize];

          // A line point is an encoding of two k bit values into one 2k bit
          // value.
          uint128_t line_point =
              encoder_.SquareToLinePoint(left_new_pos_1, left_new_pos_2);

          if (left_new_pos_1 > ((uint64_t)1 << k) ||
              left_new_pos_2 > ((uint64_t)1 << k)) {
            //            std::cout << "left and right positions too large ";
            //            std::cout << bool{line_point > ((uint128_t)1 << (2 *
            //            k))} << std::endl;
            if ((line_point > ((uint128_t)1 << (2 * k)))) {
              std::cout << "L, R: " << left_new_pos_1 << ", " << left_new_pos_2
                        << std::endl;
              std::cout << "Line point: " << line_point << std::endl;
              throw std::runtime_error("Compress line point calc loop: left "
                                       "or right positions too large");
            }
          }

          Bits to_write = Bits(line_point, 2 * k);
          to_write +=
              old_sort_keys[write_pointer_pos % kReadMinusWrite][counter];

          to_write.ToBytes(right_entry_buf.get());
          right_writer->write((const char *)right_entry_buf.get(),
                              right.entry_len);
          right.entry_cnt++;
          bucket_sizes[Util::ExtractNum(right_entry_buf.get(), right.entry_len,
                                        0, kSortBucketsLog)] += 1;
        }
      }
      current_pos += 1;
    }

    // left table not needed anymore so remove it
    temp_.get()->Advise(left.begin, left.size, MADV_REMOVE);

    std::memset(right_entry_buf.get(), 0, right.entry_len);
    right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                        right.entry_len);
    right.entry_cnt++;
    right_writer->flush();

    computation_pass_1_timer.PrintElapsed("\tFirst computation pass time:");

    // update right table size before sort
    right.size = right.entry_cnt * right.entry_len;
    {
      spare.size = right.size;
      temp_.get()->Advise(right.begin, right.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      std::cout << "\tSorting table " << int{right.id} << " 0x" << std::hex
                << right.begin << std::dec << std::endl;
      Timer sort_timer;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(right.begin, spare.begin, right.entry_len,
                                    0, bucket_sizes, sort_memory_.get(),
                                    Sort::kSortMemorySize, 1);
      sorter.diskSort(param);
      sort_timer.PrintElapsed("\tSort time:");
#ifdef USE_DROP_TABLE
      temp_.get()->Advise(spare.begin, spare.size, MADV_DONTNEED);
#endif
      temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);
    }

    Timer computation_pass_2_timer;

    right_reader->seekg(final_table_begin_pointers[right.id]);
    right_writer->seekp(final_table_begin_pointers[right.id]);

    plot_writer->seekp(final_table_begin_pointers[left.id]);
    final_entries_written = 0;

    std::vector<uint64_t> new_bucket_sizes(kNumSortBuckets, 0);
    std::vector<uint8_t> park_deltas;
    std::vector<uint64_t> park_stubs;
    uint128_t checkpoint_line_point = 0;
    uint128_t last_line_point = 0;
    uint64_t park_index = 0;

    uint64_t total_r_entries = 0;
    for (auto x : bucket_sizes) {
      total_r_entries += x;
    }

    // Now we will write on of the final tables, since we have a table sorted
    // by line point. The final table will simply store the deltas between
    // each line_point, in fixed space groups(parks), with a checkpoint in
    // each group.
    // Bits right_entry_bits;
    right.entry_cnt = total_r_entries;
    right.size = right.entry_cnt * right.entry_len;
    for (uint64_t index = 0; index < total_r_entries; index++) {
      right_reader->read(reinterpret_cast<char *>(right_entry_buf.get()),
                         right.entry_len);
      // Right entry is read as (line_point, sort_key)
      uint128_t line_point = Util::SliceInt128FromBytes(
          right_entry_buf.get(), right.entry_len, 0, 2 * k);
      uint64_t sort_key = Util::SliceInt64FromBytes(
          right_entry_buf.get(), right.entry_len, 2 * k, right_sort_key_size);

      // Write the new position (index) and the sort key
      Bits to_write = Bits(sort_key, right_sort_key_size);
      if (left.id > 1) {
        to_write += Bits(index, k + 1);
      } else {
        auto x1x2 = encoder_.LinePointToSquare(line_point);
        Bits y1 = f1.CalculateF(Bits(x1x2.first, k));
        Bits y2 = f1.CalculateF(Bits(x1x2.second, k));
        if (y1 < y2)
          to_write += Bits(x1x2.first, k);
        else
          to_write += Bits(x1x2.second, k);
      }
      assert(to_write.GetSize() < right.entry_len);
      std::memset(right_entry_buf.get(), 0, right.entry_len);
      to_write.ToBytes(right_entry_buf.get());
      right_writer->write(reinterpret_cast<char *>(right_entry_buf.get()),
                          right.entry_len);
      new_bucket_sizes[Util::ExtractNum(right_entry_buf.get(), right.entry_len,
                                        0, kSortBucketsLog)] += 1;
      // Every EPP entries, writes a park
      if (left.id > 1) {
        if (index % kEntriesPerPark == 0) {
          if (index != 0) {
            WriteParkToFile(plot_writer, final_table_begin_pointers[left.id],
                            park_index, park_size_bytes, checkpoint_line_point,
                            park_deltas, park_stubs, k, left.id);
            park_index += 1;
            final_entries_written += (park_stubs.size() + 1);
          }
          park_deltas.clear();
          park_stubs.clear();

          checkpoint_line_point = line_point;
        }
        uint128_t big_delta = line_point - last_line_point;

        // Since we have approx 2^k line_points between 0 and 2^2k, the
        // average space between them when sorted, is k bits. Much more
        // efficient than storing each line point. This is diveded into the
        // stub and delta. The stub is the least significant (k-kMinusStubs)
        // bits, and largely random/incompressible. The small delta is the
        // rest, which can be efficiently encoded since it's usually very
        // small.
        uint64_t stub =
            big_delta % (((uint128_t)1) << (uint128_t)(k - kStubMinusBits));
        uint64_t small_delta = (big_delta - stub) >> (k - kStubMinusBits);

        assert(small_delta < 256);

        if ((index % kEntriesPerPark != 0)) {
          park_deltas.push_back(small_delta);
          park_stubs.push_back(stub);
        }
        last_line_point = line_point;
      }
    }
    right_writer->flush();

    if (park_deltas.size() > 0) {
      // Since we don't have a perfect multiple of EPP entries, this writes
      // the last ones
      WriteParkToFile(plot_writer, final_table_begin_pointers[left.id],
                      park_index, park_size_bytes, checkpoint_line_point,
                      park_deltas, park_stubs, k, left.id);
    }

    if (left.id > 1) {
      std::cout << "\tWrote " << final_entries_written << " entries"
                << std::endl;
      final_table_begin_pointers[right.id] =
          final_table_begin_pointers[left.id] +
          (park_index + 1) * park_size_bytes;
    } else {
      plot_writer->seekp(final_table_begin_pointers[1]);
      final_entries_written = 0;
      uint8_t metadata_len = Util::ByteAlign(k) / 8;
      uint8_t buf[metadata_len];
      Bits num_entries(extra_metadata_hellman_.size(), k);
      num_entries.ToBytes(buf);
      plot_writer->write((const char *)buf, metadata_len);
      for (auto metadata : extra_metadata_hellman_) {
        Bits to_write(metadata, k);
        to_write.ToBytes(buf);
        plot_writer->write((const char *)buf, metadata_len);
        final_entries_written++;
      }
      plot_writer->flush();
      std::cout << "\tWrote " << final_entries_written << " entries"
                << std::endl;
      final_table_begin_pointers[right.id] =
          final_table_begin_pointers[left.id] +
          (final_entries_written + 2) * metadata_len;
    }
    plot_writer->seekp(header_size - 8 * (10 - left.id));
    uint8_t table_pointer_bytes[8 * 8];
    Bits(final_table_begin_pointers[right.id], 8 * 8)
        .ToBytes(table_pointer_bytes);
    plot_writer->write(reinterpret_cast<char *>(table_pointer_bytes), 8);
    plot_writer->flush();

    computation_pass_2_timer.PrintElapsed("\tSecond computation pass time:");
    right.size = right.entry_cnt * right.entry_len;
    {
      spare.size = right.size;
      temp_.get()->Advise(right.begin, right.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      /* This sort is needed so that in the next iteration, we can iterate
       * through both tables at ones.Note that sort_key represents y ordering,
       * and the pos, offset coordinates from forward / backprop represent
       * positions in y ordered tables. */
      std::cout << "\tRe-Sorting table " << int{right.id} << " 0x" << std::hex
                << right.begin << std::dec << std::endl;
      Timer sort_timer;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(right.begin, spare.begin, right.entry_len,
                                    0, new_bucket_sizes, sort_memory_.get(),
                                    Sort::kSortMemorySize, 0);
      sorter.diskSort(param);
      sort_timer.PrintElapsed("\tSort time:");
#ifdef USE_DROP_TABLE
      temp_.get()->Advise(spare.begin, spare.size, MADV_DONTNEED);
#endif
      temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);
    }
    table_timer.PrintElapsed("Total compress table time:");
  }
  // remove spare, there should be only table 7 available
  temp_.get()->Advise(spare.begin, spare.size, MADV_REMOVE);

#ifndef NDEBUG
  std::cout << "\nPlot tables (begin, entry-len, entry-count, size): "
            << std::endl;
  for (uint8_t i = 1; i <= 8; i++) {
    std::cout << tables_[i];
  }
#endif

  // These results will be used to write table P7 and the checkpoint tables in
  // phase 4.
  return Phase3Results{final_table_begin_pointers, final_entries_written,
                       tables_[7].entry_len * 8, header_size};
}
#endif

#endif // PLOTTER_DISK_P3_HPP
