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

#ifndef PLOTTER_DISK_P4_HPP
#define PLOTTER_DISK_P4_HPP

// Writes the checkpoint tables. The purpose of these tables, is to store a
// list of ~2^k values of size k (the proof of space outputs from table 7), in
// a way where they can be looked up for proofs, but also efficiently. To do
// this, we assume table 7 is sorted by f7, and we write the deltas between
// each f7 (which will be mostly 1s and 0s), with a variable encoding scheme
// (C3). Furthermore, we create C1 checkpoints along the way.  For example,
// every 10,000 f7 entries, we can have a C1 checkpoint, and a C3 delta
// encoded entry with 10,000 deltas.

// Since we can't store all the checkpoints in
// memory for large plots, we create checkpoints for the checkpoints (C2),
// that are meant to be stored in memory during proving. For example, every
// 10,000 C1 entries, we can have a C2 entry.

// The final table format for the checkpoints will be:
// C1 (checkpoint values)
// C2 (checkpoint values into)
// C3 (deltas of f7s between C1 checkpoints)
/////////////////////////////////////////////////////////////////////////////
void DiskPlotter::WriteCTables(uint8_t k, uint8_t pos_size,
                               Phase3Results &res) {
  std::ostream *final_file_writer_1 =
      plot_.get()->WriteHandle(Disk::WriterId::One, 0);
  std::ostream *final_file_writer_2 =
      plot_.get()->WriteHandle(Disk::WriterId::Two, 0);
  std::ostream *final_file_writer_3 =
      plot_.get()->WriteHandle(Disk::WriterId::Three, 0);

  uint32_t P7_park_size = Util::ByteAlign((k + 1) * kEntriesPerPark) / 8;
  uint64_t number_of_p7_parks =
      ((res.final_entries_written == 0 ? 0 : res.final_entries_written - 1) /
       kEntriesPerPark) +
      1;

  uint64_t begin_byte_C1 =
      res.final_table_begin_pointers[7] + number_of_p7_parks * P7_park_size;

  uint64_t total_C1_entries = std::ceil(
      res.final_entries_written / static_cast<double>(kCheckpoint1Interval));
  uint64_t begin_byte_C2 =
      begin_byte_C1 + (total_C1_entries + 1) * (Util::ByteAlign(k) / 8);
  uint64_t total_C2_entries =
      ceil(total_C1_entries / static_cast<double>(kCheckpoint2Interval));
  uint64_t begin_byte_C3 =
      begin_byte_C2 + (total_C2_entries + 1) * (Util::ByteAlign(k) / 8);

  uint32_t size_C3 = CalculateC3Size(k);
  uint64_t end_byte = begin_byte_C3 + (total_C1_entries)*size_C3;

  res.final_table_begin_pointers[8] = begin_byte_C1;
  res.final_table_begin_pointers[9] = begin_byte_C2;
  res.final_table_begin_pointers[10] = begin_byte_C3;
  res.final_table_begin_pointers[11] = end_byte;

  final_file_writer_1->seekp(begin_byte_C1);
  final_file_writer_2->seekp(begin_byte_C3);
  final_file_writer_3->seekp(res.final_table_begin_pointers[7]);

  uint64_t prev_y = 0;
  std::vector<Bits> C2;
  uint64_t num_C1_entries = 0;
  std::vector<uint8_t> deltas_to_write;
  uint32_t right_entry_size_bytes = res.right_entry_size_bits / 8;
  uint32_t size_C1 = Util::ByteAlign(k) / 8;

  // use memory allocated for sorting for buffers
  uint8_t *right_entry_buf = sort_memory_.get();
  uint8_t *C1_entry_buf = right_entry_buf + right_entry_size_bytes;
  uint8_t *C3_entry_buf = C1_entry_buf + size_C1;
  uint8_t *P7_entry_buf = C3_entry_buf + size_C3;

  // We read each table7 entry, which is sorted by f7, but we don't need f7
  // anymore. Instead, we will just store pos6, and the deltas in table C3,
  // and checkpoints in tables C1 and C2.
  {
    // init temp reader to the table 7 begin
    temp_.get()->Advise(tables_[7].begin, tables_[7].size, MADV_WILLNEED);
    std::istream *temp_reader = temp_.get()->ReadHandle(tables_[7].begin);

    m_assert(right_entry_size_bytes == tables_[7].entry_len,
             "WriteCTables: Table 7 entry length mismatch");
    m_assert(res.final_entries_written == tables_[7].entry_cnt,
             "WriteCTables: Table 7 entry count mismatch");

    ParkBits to_write_p7;
    std::cout << "\tStarting to write C1 and C3 tables" << std::endl;
    TimedSection s("\t * Writing C1 & C3 tables: ");
    for (uint64_t f7_position = 0; f7_position < res.final_entries_written;
         f7_position++) {
      temp_reader->read(reinterpret_cast<char *>(right_entry_buf),
                        right_entry_size_bytes);
      uint64_t entry_y = Util::SliceInt64FromBytes(
          right_entry_buf, right_entry_size_bytes, 0, k);
      uint64_t entry_new_pos = Util::SliceInt64FromBytes(
          right_entry_buf, right_entry_size_bytes, k, pos_size);

      Bits entry_y_bits = Bits(entry_y, k);

      if (f7_position % kEntriesPerPark == 0 && f7_position > 0) {
        std::memset(P7_entry_buf, 0, P7_park_size);
        to_write_p7.ToBytes(P7_entry_buf);
        final_file_writer_3->write(reinterpret_cast<char *>(P7_entry_buf),
                                   P7_park_size);
        to_write_p7 = ParkBits();
      }

      to_write_p7 += ParkBits(entry_new_pos, k + 1);

      if (f7_position % kCheckpoint1Interval == 0) {
        entry_y_bits.ToBytes(C1_entry_buf);
        final_file_writer_1->write(reinterpret_cast<char *>(C1_entry_buf),
                                   size_C1);
        if (num_C1_entries > 0) {
          final_file_writer_2->seekp(begin_byte_C3 +
                                     (num_C1_entries - 1) * size_C3);
          ParkBits to_write = encoder_.ANSEncodeDeltas(deltas_to_write, kC3R);
          // We need to be careful because deltas are variable sized, and they
          // need to fit
          uint64_t num_bytes = (Util::ByteAlign(to_write.GetSize()) / 8) + 2;
          assert(size_C3 * 8 > num_bytes);

          // Write the size, and then the data
          Bits(to_write.GetSize() / 8, 16).ToBytes(C3_entry_buf);
          to_write.ToBytes(C3_entry_buf + 2);

          final_file_writer_2->write(reinterpret_cast<char *>(C3_entry_buf),
                                     num_bytes);
        }
        prev_y = entry_y;
        if (f7_position % (kCheckpoint1Interval * kCheckpoint2Interval) == 0) {
          C2.emplace_back(std::move(entry_y_bits));
        }
        deltas_to_write.clear();
        ++num_C1_entries;
      } else {
        if (entry_y == prev_y) {
          deltas_to_write.push_back(0);
        } else {
          deltas_to_write.push_back(entry_y - prev_y);
        }
        prev_y = entry_y;
      }
    }
    temp_.get()->Advise(tables_[7].begin, tables_[7].size, MADV_REMOVE);

    // Writes the final park to disk
    std::memset(P7_entry_buf, 0, P7_park_size);
    to_write_p7.ToBytes(P7_entry_buf);

    final_file_writer_3->write(reinterpret_cast<char *>(P7_entry_buf),
                               P7_park_size);

    if (deltas_to_write.size() != 0) {
      // ParkBits to_write = Encoding::ANSEncodeDeltas(deltas_to_write, kC3R);
      ParkBits to_write = encoder_.ANSEncodeDeltas(deltas_to_write, kC3R);
      std::memset(C3_entry_buf, 0, size_C3);
      final_file_writer_2->seekp(begin_byte_C3 +
                                 (num_C1_entries - 1) * size_C3);

      // Writes the size, and then the data
      Bits(to_write.GetSize() / 8, 16).ToBytes(C3_entry_buf);
      to_write.ToBytes(C3_entry_buf + 2);

      final_file_writer_2->write(reinterpret_cast<char *>(C3_entry_buf),
                                 size_C3);
    }

    Bits(0, Util::ByteAlign(k)).ToBytes(C1_entry_buf);
    final_file_writer_1->write(reinterpret_cast<char *>(C1_entry_buf), size_C1);
  }
  std::cout << "\tFinished writing C1 and C3 tables" << std::endl;

  std::cout << "\tWriting C2 table" << std::endl;
  for (Bits &C2_entry : C2) {
    C2_entry.ToBytes(C1_entry_buf);
    final_file_writer_1->write(reinterpret_cast<char *>(C1_entry_buf), size_C1);
  }
  Bits(0, Util::ByteAlign(k)).ToBytes(C1_entry_buf);
  final_file_writer_1->write(reinterpret_cast<char *>(C1_entry_buf), size_C1);
  std::cout << "\tFinished writing C2 table" << std::endl;

  final_file_writer_1->seekp(res.header_size - 8 * 3);
  uint8_t table_pointer_bytes[8 * 8];

  // Writes the pointers to the start of the tables, for proving
  Bits(res.final_table_begin_pointers[8], 8 * 8).ToBytes(table_pointer_bytes);
  final_file_writer_1->write(reinterpret_cast<char *>(table_pointer_bytes), 8);
  Bits(res.final_table_begin_pointers[9], 8 * 8).ToBytes(table_pointer_bytes);
  final_file_writer_1->write(reinterpret_cast<char *>(table_pointer_bytes), 8);
  Bits(res.final_table_begin_pointers[10], 8 * 8).ToBytes(table_pointer_bytes);
  final_file_writer_1->write(reinterpret_cast<char *>(table_pointer_bytes), 8);

  // flush buffers, close final file, free temp and sort memory
  final_file_writer_1->flush();
  final_file_writer_2->flush();
  final_file_writer_3->flush();
  plot_.get()->Close();

  std::cout << "\tFinal table pointers:" << std::endl;

  std::cout << "\tP1: 0x" << std::hex << res.final_table_begin_pointers[1]
            << std::endl;
  std::cout << "\tP2: 0x" << res.final_table_begin_pointers[2] << std::endl;
  std::cout << "\tP3: 0x" << res.final_table_begin_pointers[3] << std::endl;
  std::cout << "\tP4: 0x" << res.final_table_begin_pointers[4] << std::endl;
  std::cout << "\tP5: 0x" << res.final_table_begin_pointers[5] << std::endl;
  std::cout << "\tP6: 0x" << res.final_table_begin_pointers[6] << std::endl;
  std::cout << "\tP7: 0x" << res.final_table_begin_pointers[7] << std::endl;
  std::cout << "\tC1: 0x" << res.final_table_begin_pointers[8] << std::endl;
  std::cout << "\tC2: 0x" << res.final_table_begin_pointers[9] << std::endl;
  std::cout << "\tC3: 0x" << res.final_table_begin_pointers[10] << std::dec
            << std::endl;
}

#endif // PLOTTER_DISK_P4_HPP
