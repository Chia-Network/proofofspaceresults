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

#ifndef PLOTTER_DISK_P1_HPP
#define PLOTTER_DISK_P1_HPP

inline void
DiskPlotter::CalculateFirstTable(uint8_t k, uint8_t *id,
                                 std::vector<uint64_t> &bucket_sizes,
                                 PlotTable &table, std::ostream *writer) {
  table.entry_len = GetMaxEntrySize(k, 1, true);
  table.entry_cnt = 0;
  table.size = 0;

  // The max value our input (x), can take. A proof of space is 64 of these x
  // values.
  uint64_t max_value = ((uint64_t)1 << (k)) - 1;

  std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(table.entry_len);

  // Instead of computing f1(1), f1(2), etc, for each x, we compute them in
  // batches to increase CPU efficency.
  auto entry_cnt = (((uint64_t)1) << (k - kBatchSizes));
  std::cout << "Computing table 1" << std::endl;
  Timer f1_start_time;
  uint64_t x{0};
  F1Calculator f1(k, id);
  // temp_.get()->Advise(table.begin, table.size, MADV_NORMAL);
  for (uint64_t lp = 0; lp <= entry_cnt; lp++) {
    // For each pair x, y in the batch
    for (auto kv : f1.CalculateBuckets(Bits(x, k), 2 << (kBatchSizes - 1))) {
      // TODO(mariano): fix inefficient memory alloc here
      (std::get<0>(kv) + std::get<1>(kv)).ToBytes(buf.get());

      // We write the x, y pair
      writer->write(reinterpret_cast<char *>(buf.get()), table.entry_len);
      ++table.entry_cnt;
      bucket_sizes[Util::ExtractNum(buf.get(), table.entry_len, 0,
                                    kSortBucketsLog)] += 1;

      if (x + 1 > max_value) {
        break;
      }
      ++x;
    }
    if (x + 1 > max_value) {
      break;
    }
  }
  // add zero entry
  std::memset(buf.get(), 0, table.entry_len);
  writer->write(reinterpret_cast<char *>(buf.get()), table.entry_len);
  writer->flush();
  ++table.entry_cnt;
  table.size = table.entry_cnt * table.entry_len;

  f1_start_time.PrintElapsed("F1 complete, Time = ");
}

// This is Phase 1, or forward propagation. During this phase, all of the 7
// tables, and f functions, are evaluated. The result is an intermediate plot
// file, that is several times larger than what the final file will be, but
// that has all of the proofs of space in it. First, F1 is computed, which is
// special since it uses AES256, and each encrption provides multiple output
// values. Then, the rest of the f functions are computed, and a sort on disk
// happens for each table.
/////////////////////////////////////////////////////////////////////////////
void DiskPlotter::WritePlotFile(uint8_t k, uint8_t *id, uint8_t *memo,
                                uint8_t memo_len) {

  std::ostream *writer = temp_.get()->WriteHandle();
  uint32_t header_size = WriteHeader(writer, k, id, memo, memo_len);

  // These are used for sorting on disk. The sort on disk code needs to know
  // how many elements are in each bucket.
  std::vector<uint64_t> bucket_sizes(kNumSortBuckets, 0);

  // Prepare tables vector
  tables_.reserve(12);
  PlotTable dummy{0, 0, 0, 0, 0};
  tables_.push_back(dummy);

  // Compute 1st table
  PlotTable first{1, header_size, 0, 0, 0};
  CalculateFirstTable(k, id, bucket_sizes, first, writer);
  tables_.push_back(first);

  // Store positions to previous tables, in k+1 bits. This is because we may
  // have more than 2^k entries in some of the tables, so we need an extra
  // bit.
  uint8_t pos_size = k + 1;

  // Number of buckets that y values will be put into.
  double num_buckets =
      ((uint64_t)1 << (k + kExtraBits)) / static_cast<double>(kBC) + 1;

  std::vector<uint64_t> right_bucket_sizes(kNumSortBuckets, 0);

  uint64_t max_entry_cnt = ((uint64_t)1) << k;
  uint32_t max_entry_len = GetMaxEntrySizeAll(k);

  // buffers for reading and writing to disk
  // pre-allocate space for entry buffers based on max entry length
  std::unique_ptr<uint8_t[]> left_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_len);
  std::unique_ptr<uint8_t[]> right_entry_buf =
      std::make_unique<uint8_t[]>(max_entry_len);
  uint8_t *left_buf = left_entry_buf.get();
  uint8_t *right_buf = right_entry_buf.get();

  // For tables 1 through 6, sort the table, calculate matches, and write
  // the next table. This is the left table index.
  for (uint8_t table_index = 1; table_index < 7; table_index++) {

    Timer table_timer;
    const PlotTable &left = tables_[table_index];

    // init new right (next to left) table
    PlotTable right;
    right.id = (uint8_t)(table_index + 1);
    // right table position immediately next to left table
    right.begin = left.begin + left.size;
    // max right entry length
    right.entry_len = GetMaxEntrySize(k, right.id, true);
    right.entry_cnt = 0;
    // use max size for right table size, real size calculated later
    right.size = right.entry_len * (max_entry_cnt + 1);

    // temp spare for sorting
    PlotTable spare;
    // TODO: fix this, for some strange reason sorter complains that spare
    // overlaps with given table if spare.begin == left.begin + left.size !
    // By shifting spare further one table all is OK.
    // spare.begin = right.begin + left.size;
    // I guess optimal placement for spare would be close to table that
    // is sorted.
    spare.begin = right.begin;
    spare.size = right.size;

    std::cout << "Computing table " << int{right.id} << " at 0x" << std::hex
              << right.begin << std::dec << std::endl;
    {
      temp_.get()->Advise(left.begin, left.size, MADV_RANDOM);
      temp_.get()->Advise(spare.begin, spare.size, MADV_RANDOM);
      // Perform a sort on the left table
      std::cout << "\tSorting table " << int{left.id} << " at 0x" << std::hex
                << left.begin << " using spare at 0x" << spare.begin << std::dec
                << std::endl;
      Timer sort_timer;
      Sort sorter(temp_.get());
      DSort param = Sort::makeParam(left.begin, spare.begin, left.entry_len, 0,
                                    bucket_sizes, sort_memory_.get(),
                                    Sort::kSortMemorySize, 0);
      sorter.diskSort(param);
      sort_timer.PrintElapsed("\tSort time:");
      temp_.get()->Advise(left.begin, left.size, MADV_NORMAL);
    }
    temp_.get()->Advise(right.begin, right.size, MADV_NORMAL);

    Timer computation_pass_timer;
    // Streams to read and write to tables. We will have handles to two
    // tables. We will read through the left table, compute matches, and
    // evaluate f for matching entries, writing results to the right table.
    std::istream *left_reader =
        temp_.get()->ReadHandle(Disk::ReaderId::Left, left.begin);
    std::ostream *right_writer =
        temp_.get()->WriteHandle(Disk::WriterId::Right, right.begin);

    uint8_t metadata_size = kVectorLens[right.id] * k;

    // This is a sliding window of entries, since things in bucket i can match
    // with things in bucket i + 1. At the end of each bucket, we find matches
    // between the two previous buckets.
    std::vector<PlotEntry> bucket_L;
    std::vector<PlotEntry> bucket_R;

    uint64_t bucket = 0;
    uint64_t pos = 0;          // Position into the left table
    bool end_of_table = false; // We finished all entries in the left table
    uint64_t matches = 0;      // Total matches

    // Start at left table pos = 0 and iterate through the whole table. Note
    // that the left table will already be sorted by y
    Bits zero_bits(0, metadata_size);
    FxCalculator f(k, right.id, id);
    while (!end_of_table) {
      PlotEntry left_entry;
      left_entry.right_metadata = 0;
      // Reads a left entry from disk
      left_reader->read(reinterpret_cast<char *>(left_buf), left.entry_len);
      if (table_index == 1) {
        // For table 1, we only have y and metadata
        left_entry.y = Util::SliceInt64FromBytes(left_buf, left.entry_len, 0,
                                                 k + kExtraBits);
        left_entry.left_metadata = Util::SliceInt128FromBytes(
            left_buf, left.entry_len, k + kExtraBits, metadata_size);
      } else {
        // For tables 2-6, we we also have pos and offset, but we don't use it
        // here.
        left_entry.y = Util::SliceInt64FromBytes(left_buf, left.entry_len, 0,
                                                 k + kExtraBits);
        if (metadata_size <= 128) {
          left_entry.left_metadata = Util::SliceInt128FromBytes(
              left_buf, left.entry_len, k + kExtraBits + pos_size + kOffsetSize,
              metadata_size);
        } else {
          // Large metadatas that don't fit into 128 bits. (k > 32).
          left_entry.left_metadata = Util::SliceInt128FromBytes(
              left_buf, left.entry_len, k + kExtraBits + pos_size + kOffsetSize,
              128);
          left_entry.right_metadata = Util::SliceInt128FromBytes(
              left_buf, left.entry_len,
              k + kExtraBits + pos_size + kOffsetSize + 128,
              metadata_size - 128);
        }
      }
      // This is not the pos that was read from disk,but the position of the
      // entry we read, within L table.
      left_entry.pos = pos;
      end_of_table = (left_entry.y == 0 && left_entry.left_metadata == 0 &&
                      left_entry.right_metadata == 0);
      uint64_t y_bucket = left_entry.y / kBC;

      // Keep reading left entries into bucket_L and R, until we run out of
      // things
      if (y_bucket == bucket) {
        bucket_L.emplace_back(std::move(left_entry));
      } else if (y_bucket == bucket + 1) {
        bucket_R.emplace_back(std::move(left_entry));
      } else {
        // This is reached when we have finished adding stuff to bucket_R and
        // bucket_L, so now we can compare entries in both buckets to find
        // matches. If two entries match, the result is written to the right
        // table.
        if (bucket_L.size() > 0 && bucket_R.size() > 0) {
          // Compute all matches between the two buckets, and return indeces
          // into each bucket
#ifdef USE_HELLMAN_ATTACK
          std::vector<std::pair<uint16_t, uint16_t>> match_indexes =
              f.FindMatchesHellman(bucket_L, bucket_R);
#else
          std::vector<std::pair<uint16_t, uint16_t>> match_indexes =
              f.FindMatches(bucket_L, bucket_R);
#endif
          for (auto &indeces : match_indexes) {
            PlotEntry &L_entry = bucket_L[std::get<0>(indeces)];
            PlotEntry &R_entry = bucket_R[std::get<1>(indeces)];
            std::pair<Bits, Bits> f_output;

            // Computes the output pair (fx, new_metadata)
            if (metadata_size <= 128) {
              f_output =
                  f.CalculateBucket(Bits(L_entry.y, k + kExtraBits),
                                    /* Bits(R_entry.y, k + kExtraBits), */
                                    Bits(L_entry.left_metadata, metadata_size),
                                    Bits(R_entry.left_metadata, metadata_size));
            } else {
              // Metadata does not fit into 128 bits
              f_output = f.CalculateBucket(
                  Bits(L_entry.y, k + kExtraBits),
                  /* Bits(R_entry.y, k + kExtraBits), */
                  Bits(L_entry.left_metadata, 128) +
                      Bits(L_entry.right_metadata, metadata_size - 128),
                  Bits(R_entry.left_metadata, 128) +
                      Bits(R_entry.right_metadata, metadata_size - 128));
            }
            // fx/y, which will be used for sorting and matching
            Bits &new_entry = std::get<0>(f_output);
            ++matches;

            if (table_index + 1 == 7) {
              // We only need k instead of k + kExtraBits bits for the last
              // table
              new_entry = new_entry.Slice(0, k);
            }
            // Position in the previous table
            new_entry += Bits(L_entry.pos, pos_size);
            new_entry.AppendValue(R_entry.pos - L_entry.pos, kOffsetSize);
            // New metadata which will be used to compute the next f
            new_entry += std::get<1>(f_output);
            // Fill with 0s if entry is not long enough
            new_entry.AppendValue(0, right.entry_len * 8 - new_entry.GetSize());
            new_entry.ToBytes(right_buf);
            // Writes the new entry into the right table
            right_writer->write(reinterpret_cast<char *>(right_buf),
                                right.entry_len);
            ++right.entry_cnt;

            // Computes sort bucket, so we can sort the table by y later, more
            // easily
            right_bucket_sizes[Util::ExtractNum(right_buf, right.entry_len, 0,
                                                kSortBucketsLog)] += 1;
          }
        }
        if (y_bucket == bucket + 2) {
          // We saw a bucket that is 2 more than the current, so we just set L
          // = R, and R = [entry]
          bucket_L = bucket_R;
          bucket_R = std::vector<PlotEntry>();
          bucket_R.emplace_back(std::move(left_entry));
          ++bucket;
        } else {
          // We saw a bucket that >2 more than the current, so we just set L =
          // [entry], and R = []
          bucket = y_bucket;
          bucket_L = std::vector<PlotEntry>();
          bucket_L.emplace_back(std::move(left_entry));
          bucket_R = std::vector<PlotEntry>();
        }
      }
      // Increase the read pointer in the left table, by one
      ++pos;
    }
#ifdef USE_DROP_TABLE
    // drop left table
    temp_.get()->Advise(left.begin, left.size, MADV_DONTNEED);
#endif

    // Total matches found in the left table
    std::cout << "\tTotal matches: " << matches
              << ". Per bucket: " << (matches / num_buckets) << std::endl;

    // Writes the 0 entry (EOT)
    std::memset(right_buf, 0, right.entry_len);
    right_writer->write(reinterpret_cast<char *>(right_buf), right.entry_len);
    ++right.entry_cnt;

    // Writes the start of the table to the header, so we can resume plotting
    // if it interrups.
    uint8_t pointer_buf[8];
    Bits(right.begin, 8 * 8).ToBytes(pointer_buf);
    right_writer->seekp(header_size - 8 * (12 - table_index));
    right_writer->write(reinterpret_cast<char *>(pointer_buf), 8);

    // calc real right size and add table into vector
    right.size = right.entry_cnt * right.entry_len;
    tables_.push_back(right);

    // Resets variables
    bucket_sizes = right_bucket_sizes;
    right_bucket_sizes = std::vector<uint64_t>(kNumSortBuckets, 0);

    computation_pass_timer.PrintElapsed("\tComputation pass time:");
    table_timer.PrintElapsed("Forward propagation table time:");
  }
  //    temp_.get()->Sync();

  // add spare table for sorting
  PlotTable spare{8, tables_[7].begin + tables_[7].size, 0, 0, 0};
  tables_.push_back(spare);

  std::cout << "\nPlot tables (begin, entry-len, entry-count, size): "
            << std::endl;
  for (uint8_t i = 1; i <= 8; i++) {
    std::cout << tables_[i];
  }
}

#endif // PLOTTER_DISK_P1_HPP
