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

#ifndef FILE_DISK_HPP
#define FILE_DISK_HPP

#include <algorithm>
#include <cmath>
#include <cstdio>

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std {
using namespace experimental;
}
#else
#error !
#endif

#include <fstream>
#include <iostream>
#include <istream>
#include <iterator>
#include <ostream>
#include <streambuf>
#include <string>
#include <vector>

#include <ext/stdio_filebuf.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#include "pos_constants.hpp"
#include "util.hpp"

constexpr size_t kMemoryMapRegionSize = (2_GB);
constexpr size_t kDefaultFileSize = 4_GB;

/**
 * @brief The Disk class
 */
class Disk {
public:
  enum class AccessMode : uint8_t { ReadWrite = 0, ReadOnly };
  enum class ReaderId : uint8_t { Left = 0, Right };
  enum class WriterId : uint8_t { Left = 0, Right, One, Two, Three };

  virtual ~Disk() {}
  virtual void Open() {}
  virtual void Close() {}
  virtual void Sync() {}

  virtual void Read(uint64_t begin, uint8_t *memcache, uint32_t length) = 0;
  virtual void Write(uint64_t begin, uint8_t *memcache, uint32_t length) = 0;
  virtual std::istream *ReadHandle(uint64_t begin = 0) = 0;
  virtual std::ostream *WriteHandle(uint64_t begin = 0) = 0;

  virtual u_int64_t GetStreamBufferSize() const = 0;

  /////////////////////////////////////////////////////////////////////////////
  virtual std::istream *ReadHandle([[maybe_unused]] ReaderId id,
                                   [[maybe_unused]] uint64_t begin) {
    return nullptr;
  }
  /////////////////////////////////////////////////////////////////////////////
  virtual std::ostream *WriteHandle([[maybe_unused]] WriterId id,
                                    [[maybe_unused]] uint64_t begin) {
    return nullptr;
  }
  /////////////////////////////////////////////////////////////////////////////
  virtual int Advise([[maybe_unused]] uint64_t offset,
                     [[maybe_unused]] size_t length,
                     [[maybe_unused]] int advice) {
    return -1;
  }

  /////////////////////////////////////////////////////////////////////////////
  virtual void AdviseReset() {}

private:
  /////////////////////////////////////////////////////////////////////////////
  static const inline std::map<int, uint64_t> kWorkspaceFileSize = {
      {15, 2_MB},   {16, 5_MB},   {17, 10_MB},  {18, 25_MB},  {19, 50_MB},
      {20, 100_MB}, {21, 250_MB}, {22, 500_MB}, {23, 1_GB},   {24, 2_GB},
      {25, 4_GB},   {26, 8_GB},   {27, 16_GB},  {28, 34_GB},  {29, 68_GB},
      {30, 136_GB}, {31, 272_GB}, {32, 544_GB}, {33, 1088_GB}};

protected:
  /////////////////////////////////////////////////////////////////////////////
  uint64_t alloc_space(const std::string &filename, uint64_t fsize) {

    // remove existing file
    if (std::filesystem::exists(filename))
      std::filesystem::remove(filename);

    // create empty file
    std::fstream f(filename, std::fstream::out | std::fstream::app |
                                 std::fstream::binary);
    f << std::flush;
    f.close();
    if (fsize == 0)
      return 0;

#if 0
    // find new file size from map
    uint64_t fsize = kDefaultFileSize;
    auto it = kWorkspaceFileSize.find(k);
    if (it != kWorkspaceFileSize.end())
      fsize = it->second;
#endif

    // resize file
    if (fsize < std::filesystem::space(filename).free) {
      std::filesystem::resize_file(filename, fsize);
    } else {
      throw std::runtime_error("Disk: not enough free space");
    }
    // insert zero into eof
    f.open(filename, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(int64_t(fsize));
    f.put('0');
    f.seekg(int64_t(fsize));
    char v;
    f.get(v);
    assert(v == '0');
    f.close();
    std::cout << "Initial workspace file: " << filename
              << ", size: " << std::filesystem::file_size(filename)
              << "\nFilesystem free space: "
              << std::filesystem::space(filename).free << std::endl;
    return fsize;
  }
};

/**
 * @brief The FileDisk class
 */
class FileDisk : public Disk {
public:
  /////////////////////////////////////////////////////////////////////////////
  inline explicit FileDisk(
      const std::string &filename, uint64_t disk_space = 0,
      [[maybe_unused]] Disk::AccessMode mode = Disk::AccessMode::ReadWrite) {
    fname_ = filename;
    fsize_ = 0;
    fp_ = nullptr;
    buf_ = std::make_unique<char[]>(kStreamBufferSize);
    inbuf_ = std::make_unique<char[]>(kStreamBufferSize);
    outbuf_ = std::make_unique<char[]>(kStreamBufferSize);

    if (disk_space != 0)
      fsize_ = alloc_space(filename, disk_space);
    else {
      // create empty file
      std::fstream f(filename, std::fstream::out | std::fstream::app |
                                   std::fstream::binary);
      f << std::flush;
      f.close();
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  ~FileDisk() override { Close(); }

  /////////////////////////////////////////////////////////////////////////////
  inline void Open() override {
    // Opens the main file stream for buffered read/write
    fs_.open(fname_, rw_mode_);
    fs_.rdbuf()->pubsetbuf(buf_.get(), kStreamBufferSize);
    if (!fs_.is_open())
      throw std::runtime_error("FileDisk.Open: file stream open failed");
    // prepare additional I/O
    open_io();
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Close() override {
    close_io();

    if (fs_.is_open()) {
      fs_.flush();
      fs_.close();
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Read(uint64_t begin, uint8_t *memcache,
                   uint32_t length) override {
    fs_.seekg(static_cast<int64_t>(begin));
    fs_.read(reinterpret_cast<char *>(memcache), length);
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Write(uint64_t begin, uint8_t *memcache,
                    uint32_t length) override {
    fs_.seekp(static_cast<int64_t>(begin));
    fs_.write(reinterpret_cast<char *>(memcache), length);
    fs_.flush();
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::istream *ReadHandle(uint64_t begin = 0) override {
    fs_.seekg(static_cast<int64_t>(begin));
    return (&fs_);
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::ostream *WriteHandle(uint64_t begin = 0) override {
    fs_.seekp(static_cast<int64_t>(begin));
    return &fs_;
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::istream *ReadHandle(ReaderId id, uint64_t begin = 0) override {
    input_[static_cast<uint8_t>(id)].seekg(static_cast<int64_t>(begin));
    return (&input_[static_cast<uint8_t>(id)]);
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::ostream *WriteHandle(WriterId id, uint64_t begin = 0) override {
    output_[static_cast<uint8_t>(id)].seekp(static_cast<int64_t>(begin));
    return (&output_[static_cast<uint8_t>(id)]);
  }

  inline uint64_t GetStreamBufferSize() const override {
    return kStreamBufferSize;
  }

  // NOTE: system defined BUFSIZ for buffered file stream I/O is 8192
  static constexpr uint64_t kStreamBufferSize = 256_KB;

private:
  std::string fname_;
  uint64_t fsize_;
  std::fstream fs_;
  std::array<std::ifstream, 2> input_;
  std::array<std::ofstream, 5> output_;
  std::FILE *fp_;

  // data buffer for main file io stream 'fs'
  std::unique_ptr<char[]> buf_;

  // NOTE: to use shared data buffers for read/write, it requires
  // that these operations don't overlap.
  // shared data buffer for reader streams
  std::unique_ptr<char[]> inbuf_;
  // shared data buffer for writer streams
  std::unique_ptr<char[]> outbuf_;

  static constexpr std::ios_base::openmode rw_mode_ =
      std::fstream::in | std::fstream::out | std::fstream::binary;
  static constexpr std::ios_base::openmode ro_mode_ =
      std::fstream::in | std::fstream::binary;

  /////////////////////////////////////////////////////////////////////////////
  inline void open_io() {
    for (auto i = 0u; i < input_.size(); i++)
      open_input(input_[i]);
    for (auto i = 0u; i < output_.size(); i++)
      open_output(output_[i]);

#if defined(_POSIX_VERSION)
    fp_ = std::fopen(fname_.c_str(), "r+b");
    if (!fp_)
      throw std::runtime_error("Disk.open_io: Posix FILE* open failed");

    // set some sort of low level buffering to recommended size
    // TODO: find out if this has any effect or just overlap with the
    // fstream buf setting
    struct stat64 stats;
    ::fstat64(fileno(fp_), &stats);
    size_t bs = static_cast<uint64_t>(stats.st_blksize);
    // use internal buffers, full buffering mode
    std::setvbuf(fp_, nullptr, _IOFBF, bs);
    // advice kernel of access pattern
    ::posix_fadvise(fileno(fp_), 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void close_io() {
    for (auto i = 0u; i < input_.size(); i++) {
      if (input_[i].is_open())
        input_[i].close();
    }
    for (auto i = 0u; i < output_.size(); i++) {
      if (output_[i].is_open()) {
        output_[i].flush();
        output_[i].close();
      }
    }

    if (fp_) {
      std::fclose(fp_);
      fp_ = nullptr;
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void open_input(std::ifstream &ifs) {
    ifs.open(fname_, ro_mode_);
    ifs.rdbuf()->pubsetbuf(inbuf_.get(), kStreamBufferSize);
    if (!ifs.is_open())
      throw std::runtime_error("FileDisk.open_input: file open failed");
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void open_output(std::ofstream &ofs) {
    ofs.open(fname_, rw_mode_);
    ofs.rdbuf()->pubsetbuf(outbuf_.get(), kStreamBufferSize);
    if (!ofs.is_open())
      throw std::runtime_error("FileDisk.open_output: file open failed");
  }
};

#endif /* FILE_DISK_HPP */
