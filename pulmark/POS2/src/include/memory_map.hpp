// Copyright 2019 Chia Network Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MEMORY_MAP_HPP
#define MEMORY_MAP_HPP

#include <unistd.h>

#include "file_disk.hpp"
#include "mio.hpp"

// #define MMAP_REGION true

/**
 * @brief immapbuf class - Basic streambuffer to read data from memory
 * region using std::istream interface. The buffer has pointers into
 * memory map begin, end region and current read position.
 */
template <typename Byte = uint8_t> class immapbuf : public std::streambuf {
public:
  using byte = Byte;
  static_assert(1 == sizeof(byte), "sizeof buffer element type 1.");

  immapbuf(const byte *data, size_t len)
      : // data + size
        begin_(data), end_(data + len), current_(data) {}

  immapbuf(const byte *beg, const byte *end)
      : // begin + end
        begin_(beg), end_(end), current_(beg) {}

  void reset(const byte *begin, const byte *end) {
    begin_ = begin;
    end_ = end;
    current_ = begin_;
    offset_ = 0;
  }

protected:
  inline int_type underflow() override {
    return (current_ == end_ ? traits_type::eof()
                             : traits_type::to_int_type(*current_));
  }

  inline int_type uflow() override {
    return (current_ == end_ ? traits_type::eof()
                             : traits_type::to_int_type(*current_++));
  }

  inline int_type pbackfail(int_type ch) override {
    if (current_ == begin_ ||
        (ch != traits_type::eof() && ch != *(current_ - 1)))
      return traits_type::eof();

    return traits_type::to_int_type(*--current_);
  }

  inline std::streamsize showmanyc() override {
    assert(std::less_equal<const char *>()(current_, end_));
    return end_ - current_;
  }

  inline std::streampos seekoff(std::streamoff off, std::ios::seekdir way,
                                std::ios::openmode which) override {
    if (which & std::ios::ios_base::out) {
      return (-1);
    }

    offset_ = -1;
    if (way == std::ios_base::beg) {
      if (begin_ + off >= begin_ && begin_ + off < end_) {
        current_ = begin_ + off;
        offset_ = current_ - begin_;
      }
    }
    if (way == std::ios_base::end)
      if (end_ + off >= begin_ && end_ + off < end_) {
        current_ = end_ + off;
        offset_ = current_ - begin_;
      }
    if (way == std::ios_base::cur)
      if (current_ + off >= begin_ && current_ + off < end_) {
        current_ = current_ + off;
        offset_ = current_ - begin_;
      }
    assert(current_ >= begin_ && current_ < end_);
    m_assert(offset_ >= 0, "invalid seek offset");
    return offset_;
  }

  inline std::streampos seekpos(std::streampos sp,
                                std::ios_base::openmode which) override {
    if (which & std::ios::ios_base::out) {
      return (-1);
    }

    offset_ = -1;
    if (begin_ + sp >= begin_ && begin_ + sp < end_) {
      current_ = begin_ + sp;
      offset_ = sp;
    }
    assert(current_ >= begin_ && current_ < end_);
    m_assert(offset_ >= 0, "invalid seek position");
    return offset_;
  }

#if 0
  template <typename _CharT, typename _Traits>
  std::streamsize
  std::basic_streambuf<_CharT, _Traits>::xsgetn(char_type *__s,
                                                std::streamsize __n) {
    std::streamsize __ret = 0;
    while (__ret < __n) {
      const std::streamsize __buf_len = this->egptr() - this->gptr();
      if (__buf_len) {
        const std::streamsize __remaining = __n - __ret;
        const std::streamsize __len = std::min(__buf_len, __remaining);
        traits_type::copy(__s, this->gptr(), __len);
        __ret += __len;
        __s += __len;
        this->__safe_gbump(__len);
      }

      if (__ret < __n) {
        const int_type __c = this->uflow();
        if (!traits_type::eq_int_type(__c, traits_type::eof())) {
          traits_type::assign(*__s++, traits_type::to_char_type(__c));
          ++__ret;
        } else
          break;
      }
    }
    return __ret;
  }
#endif

  inline std::streamsize xsgetn(char *s, std::streamsize n) override {
    auto cnt = (current_ + n) < end_ ? n : end_ - current_;
    std::memcpy(s, current_, cnt);
    current_ += cnt;
    if (cnt != n) {
#ifndef NDEBUG
      std::cout << "immapbuf read: end - begin = " << end_ - begin_
                << std::endl;
      std::cout << "immapbuf read: end - current = " << end_ - current_
                << std::endl;
      std::cout << "immapbuf read: n = " << n << ", cnt = " << cnt
                << ", stream offset = " << offset_ << std::endl;
      std::cout << "immapbuf read: extra size required = "
                << n - (end_ - current_) << std::endl;
#endif
      throw std::runtime_error("Memory-map.read: Pre-allocated file too small");
    }
    return cnt;
  }

  //  virtual int sync();

  const byte *begin_;
  const byte *end_;
  const byte *current_;
  // offset within [begin, end)
  std::streampos offset_;
};

/**
 * @brief ommapbuf class - Basic streambuffer to write data into memory
 * region using std::ostream interface. The buffer has pointers into
 * memory map begin, end region and current write position.
 */
template <typename Byte = uint8_t> class ommapbuf : public std::streambuf {
public:
  using byte = Byte;
  static_assert(1 == sizeof(byte), "sizeof buffer element type 1.");

  ommapbuf(byte *data, size_t len)
      : // ptr + size
        begin_(data), end_(data + len), current_(data) {}

  ommapbuf(byte *beg, const byte *end)
      : // begin + end
        begin_(beg), end_(end), current_(beg) {}

  void reset(byte *begin, byte *end) {
    begin_ = begin;
    end_ = end;
    current_ = begin_;
    offset_ = 0;
  }

protected:
  inline int_type overflow(int_type ch) override {
    if (traits_type::eq_int_type(ch, traits_type::eof()))
      return traits_type::not_eof(ch);

    if (current_ >= end_)
      return traits_type::eof();

    *current_ = traits_type::to_char_type(ch);
    current_++;
    return ch;
  }

  inline std::streampos seekoff(std::streamoff off, std::ios::seekdir way,
                                std::ios::openmode which) override {
    if (which & std::ios::ios_base::in) {
      assert(0);
      return (-1);
    }

    offset_ = -1;
    if (way == std::ios_base::beg) {
      if (begin_ + off >= begin_ && begin_ + off < end_) {
        current_ = begin_ + off;
        offset_ = current_ - begin_;
      }
    }
    if (way == std::ios_base::end)
      if (end_ + off >= begin_ && end_ + off < end_) {
        current_ = end_ + off;
        offset_ = current_ - begin_;
      }
    if (way == std::ios_base::cur)
      if (current_ + off >= begin_ && current_ + off < end_) {
        current_ = current_ + off;
        offset_ = current_ - begin_;
      }
    assert(current_ >= begin_ && current_ < end_);
    m_assert(offset_ >= 0, "invalid seek offset");
    return offset_;
  }

  inline std::streampos seekpos(std::streampos sp,
                                std::ios_base::openmode which) override {
    if (which & std::ios::ios_base::in) {
      assert(0);
      return (-1);
    }

    offset_ = -1;
    if (begin_ + sp >= begin_ && begin_ + sp < end_) {
      current_ = begin_ + sp;
      offset_ = sp;
    }
    assert(current_ >= begin_ && current_ < end_);
    m_assert(offset_ >= 0, "invalid seek position");
    return offset_;
  }

  inline std::streamsize xsputn(const char *s, std::streamsize n) override {
    auto cnt = (current_ + n) < end_ ? n : end_ - current_;
    std::memcpy(current_, s, cnt);
    current_ += cnt;
    m_assert(cnt == n, "less bytes written than requested");
    if (cnt != n) {
#ifndef NDEBUG
      std::cout << "ommapbuf write: end - begin = " << end_ - begin_
                << std::endl;
      std::cout << "ommapbuf write: end - current = " << end_ - current_
                << std::endl;
      std::cout << "ommapbuf write: n = " << n << ", cnt = " << cnt
                << ", stream offset = " << offset_ << std::endl;
      std::cout << "ommapbuf write: extra size required = "
                << n - (end_ - current_) << std::endl;
#endif
      throw std::runtime_error(
          "Memory-map.write: Pre-allocated file too small");
    }
    return cnt;
  }

  //  virtual int sync();

  byte *begin_;
  byte *end_;
  byte *current_;
  // offset within [begin, end)
  std::streampos offset_;
};

/**
 * @brief MemoryMapMioDisk class - memory mapping, uses mio header only libray
 * for memory mapping internal implementation. The class provides std I/O stream
 * API to access memory mapped region.
 */
class MemoryMapMioDisk : public Disk {
public:
  /////////////////////////////////////////////////////////////////////////////
  inline explicit MemoryMapMioDisk(const std::string &filename,
                                   uint64_t disk_space, Disk::AccessMode mode)
      : fname_(filename), mode_(mode) {
    if (mode_ == Disk::AccessMode::ReadWrite)
      fsize_ = alloc_space(filename, disk_space);

    init_mmap();
  }

  /////////////////////////////////////////////////////////////////////////////
  inline ~MemoryMapMioDisk() override {
    Sync();

    delete is_;

    if (mode_ == Disk::AccessMode::ReadWrite) {
      delete os_;
      for (size_t i = 0; i < input_.size(); i++)
        delete input_[i];
      for (size_t i = 0; i < output_.size(); i++)
        delete output_[i];
    }

    {
#ifndef NDEBUG
      TimedSection s("* Memory map unmap:");
#endif
      if (mode_ == Disk::AccessMode::ReadWrite) {
#ifdef USE_MADVISE
        ::madvise(rw_mmap_.begin(), rw_mmap_.mapped_length(), MADV_REMOVE);
#endif
        rw_mmap_.unmap();
      } else {
#ifdef USE_MADVISE
        ::madvise((void *)(ro_mmap_.begin()), ro_mmap_.mapped_length(),
                  MADV_REMOVE);
#endif
        ro_mmap_.unmap();
      }
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Sync() override {
    if (mode_ == Disk::AccessMode::ReadOnly)
      return;

#ifndef NDEBUG
    TimedSection s("* Memory map sync:");
#endif
    rw_mmap_.sync(err_);
    if (err_) {
      handle_error(err_);
      throw std::runtime_error("memory map sync failed");
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  inline int Advise([[maybe_unused]] uint64_t offset,
                    [[maybe_unused]] size_t length,
                    [[maybe_unused]] int advice) override __attribute((hot)) {
#ifndef USE_MADVISE
    return -1;
#else
    void *first = rw_mmap_.begin() + offset;
    //    void *last = rw_mmap_.data() + offset + length + psize_;
    auto aligned_first = (void *)((unsigned long)(first) / psize_ * psize_);
    //    auto align_last = (void *)((unsigned long)(last) / psize_ * psize_);
    //    auto len = (uint8_t *)(align_last) - (uint8_t *)(align_first);
    auto err = ::madvise(aligned_first, length, advice);
    // #ifndef NDEBUG
    if (err) {
      std::cerr << "MemoryMap::Advice() call failed: err = " << err;
      std::cerr << ", offset = " << offset << ", length = " << length;
      std::cerr << ", advice = " << advice << ", aligned = 0x" << std::hex
                << aligned_first << std::dec << std::endl;
    }
    // #endif
    return err;
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void AdviseReset() override __attribute((hot)) {
#ifdef USE_MADVISE
    if (rw_mmap_.is_mapped()) {
      Advise(0, rw_mmap_.mapped_length(), kMemAdviceModeReadWrite);
    }
    if (ro_mmap_.is_mapped()) {
      Advise(0, ro_mmap_.mapped_length(), kMemAdviceModeReadOnly);
    }
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Read(uint64_t begin, uint8_t *buf, uint32_t len) override
      __attribute((hot)) {
#ifdef USE_ITERATOR_ACCESS
    if (rw_mmap_.is_mapped())
      std::copy_n(rw_mmap_.begin() + begin, len, buf);
    else if (ro_mmap_.is_mapped())
      std::copy_n(ro_mmap_.begin() + begin, len, buf);
#else
    is_->seekg(begin);
    is_->read(reinterpret_cast<char *>(buf), len);
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  inline void Write(uint64_t begin, uint8_t *buf, uint32_t len) override
      __attribute((hot)) {
#ifdef USE_ITERATOR_ACCESS
    std::copy_n(buf, len, rw_mmap_.begin() + begin);
#else
    os_->seekp(begin);
    os_->write(reinterpret_cast<char *>(buf), len);
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::istream *ReadHandle(uint64_t begin = 0) override
      __attribute((hot)) {
    is_->seekg(begin);
    return is_;
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::ostream *WriteHandle(uint64_t begin = 0) override
      __attribute((hot)) {
    os_->seekp(begin);
    return os_;
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::istream *ReadHandle(ReaderId id, uint64_t begin = 0) override
      __attribute((hot)) {
    input_[static_cast<uint8_t>(id)]->seekg(begin);
    return input_[static_cast<uint8_t>(id)];
  }

  /////////////////////////////////////////////////////////////////////////////
  inline std::ostream *WriteHandle(WriterId id, uint64_t begin = 0) override
      __attribute((hot)) {
    output_[static_cast<uint8_t>(id)]->seekp(begin);
    return output_[static_cast<uint8_t>(id)];
  }

  inline uint64_t GetStreamBufferSize() const override {
    return kStreamBufferSize;
  }

  // size of buffered I/O for sorter
  static constexpr uint64_t kStreamBufferSize = 256_KB;

private:
  std::string fname_;
  size_t fsize_;
  int64_t psize_;
  size_t first_;
  size_t last_;
  std::error_code err_;
  Disk::AccessMode mode_;

  static constexpr int kMemAdviceModeReadWrite = MADV_NORMAL;
  static constexpr int kMemAdviceModeReadOnly = MADV_NORMAL;

  std::istream *is_;
  std::ostream *os_;
  std::array<std::istream *, 2> input_;

  std::array<std::ostream *, 5> output_;
  std::unique_ptr<ommapbuf<char>> obuf_;
  std::unique_ptr<immapbuf<char>> ibuf_;
  std::unique_ptr<immapbuf<char>> ibuf_add_[2];
  std::unique_ptr<ommapbuf<char>> obuf_add_[5];

  mio::mmap_sink rw_mmap_;
  mio::mmap_source ro_mmap_;

  /////////////////////////////////////////////////////////////////////////////
  inline void init_mmap() {
    // mem page size
    psize_ = ::sysconf(_SC_PAGESIZE);

    // create mapping using mio
    if (mode_ == Disk::AccessMode::ReadWrite) {
#ifdef MMAP_REGION
      if (fsize_ > kMemoryMapRegionSize)
        rw_mmap_ = mio::make_mmap_sink(fname_, 0, kMemoryMapRegionSize, err_);
      else
#endif
        rw_mmap_ = mio::make_mmap_sink(fname_, 0, mio::map_entire_file, err_);
      first_ = 0;
      last_ = rw_mmap_.size();
#ifdef USE_MADVISE
      ::madvise(rw_mmap_.begin(), rw_mmap_.mapped_length(), MADV_NORMAL);
#endif
    } else {
      ro_mmap_ = mio::make_mmap_source(fname_, 0, mio::map_entire_file, err_);
      first_ = 0;
      last_ = ro_mmap_.size();
#ifdef USE_MADVISE
      ::madvise((void *)(ro_mmap_.begin()), ro_mmap_.mapped_length(),
                MADV_NORMAL);
#endif
    }

    if (err_) {
      handle_error(err_);
      throw std::runtime_error("MemoryMap.init_mmap: memory map create failed");
    }

    // init I/O buffers & streams to access memory-mapped region

    // for read-only mapping only single input buf/stream
    if (mode_ == Disk::AccessMode::ReadOnly) {
      ibuf_ =
          std::make_unique<immapbuf<char>>(ro_mmap_.data(), ro_mmap_.size());
      is_ = new std::istream(ibuf_.get());
      return;
    }

    // for read-write mapping main buf/stream and additional bufs/streams
    ibuf_ = std::make_unique<immapbuf<char>>(rw_mmap_.data(), rw_mmap_.size());
    obuf_ = std::make_unique<ommapbuf<char>>(rw_mmap_.data(), rw_mmap_.size());

    // additional buffers
    for (auto i = 0; i < 5; i++) {
      obuf_add_[i] =
          std::make_unique<ommapbuf<char>>(rw_mmap_.data(), rw_mmap_.size());
    }
    for (auto i = 0; i < 2; i++) {
      ibuf_add_[i] =
          std::make_unique<immapbuf<char>>(rw_mmap_.data(), rw_mmap_.size());
    }

    // basic io streams
    is_ = new std::istream(ibuf_.get());
    os_ = new std::ostream(obuf_.get());

    // additional streams
    for (size_t i = 0; i < input_.size(); i++)
      input_[i] = new std::istream(ibuf_add_[i].get());
    for (size_t i = 0; i < output_.size(); i++)
      output_[i] = new std::ostream(obuf_add_[i].get());
  }

  /////////////////////////////////////////////////////////////////////////////
  inline int handle_error(const std::error_code &error) {
    const auto &errmsg = error.message();
    std::printf("error un(mapping) file: %s, exiting...\n", errmsg.c_str());
    return error.value();
  }
};

#if 0
/////////////////////////////////////////////////////////////////////////////
inline void ReMap(const size_t begin, const size_t length,
                  Disk::AccessMode mode) {
  bool isModeChange(mode_ != mode);
  do {
    if (mode == Disk::AccessMode::ReadWrite) {
      if (isModeChange) {
        ro_mmap_.unmap();
        rw_mmap_.map(fname_, begin, length, err_);
        break;
      }
      rw_mmap_.sync(err_);
      if (err_)
        break;
      rw_mmap_.unmap();
      rw_mmap_.map(fname_, begin, length, err_);
      break;
    }
    if (mode == Disk::AccessMode::ReadOnly) {
      if (isModeChange) {
        rw_mmap_.sync(err_);
        if (err_)
          break;
        rw_mmap_.unmap();
        ro_mmap_.map(fname_, begin, length, err_);
        break;
      }
      ro_mmap_.unmap();
      ro_mmap_.map(fname_, begin, length, err_);
    }
  } while (0);

  if (err_) {
    handle_error(err_);
    throw std::runtime_error("MemoryMap.remmap failed");
  }
  mode_ = mode;
}

/////////////////////////////////////////////////////////////////////////////
inline void check_remmap(const size_t begin, const size_t end) {
  // no remapping for read-only files
  if (mode_ == Disk::AccessMode::ReadOnly)
    return;

  // check if begin, end is within currently mapped region
  if (begin >= first_ && end < last_)
    return;

  // sync, remap
  rw_mmap_.sync(err_);
  if (err_) {
    handle_error(err_);
    throw std::runtime_error(
        "MemoryMap.check_remmap: memory map sync failed");
  }
  rw_mmap_.unmap();

  // align new mapping into page size, calc mapped region
  first_ = (begin / psize_) * psize_;
  auto len = ((first_ + kMemoryMapRegionSize) < fsize_) ? kMemoryMapRegionSize
                                                        : fsize_ - first_;
  rw_mmap_.map(fname_, first_, len, err_);
  if (err_) {
    handle_error(err_);
    throw std::runtime_error(
        "MemoryMap.check_remmap: new memory mapping failed");
  }

  last_ = first_ + rw_mmap_.length();

  // reset i/o buffers
  obuf_.get()->reset(rw_mmap_.begin(), rw_mmap_.end());
  ibuf_.get()->reset(rw_mmap_.begin(), rw_mmap_.end());

  for (auto i = 0; i < 5; i++) {
    obuf_add_[i].get()->reset(rw_mmap_.begin(), rw_mmap_.end());
  }
  for (auto i = 0; i < 2; i++) {
    ibuf_add_[i].get()->reset(rw_mmap_.begin(), rw_mmap_.end());
  }

#ifndef NDEBUG
  std::cout << "\t* remmap::begin = " << begin << std::endl;
  std::cout << "\t* remmap::region = [" << first_ << "," << last_ << "]"
            << std::endl;
  std::cout << "\t* remmap::mapped length = " << rw_mmap_.mapped_length()
            << std::endl;
  std::cout << "\t* remmap::mapping offset = " << rw_mmap_.mapping_offset()
            << std::endl;
  std::cout << "\t* remmap::size = " << rw_mmap_.size() << std::endl;
  std::cout << "\t* remmap::kMemoryMapRegionSize = " << kMemoryMapRegionSize
            << std::endl;
#endif
}
#endif

#endif // MEMORY_MAP_HPP
