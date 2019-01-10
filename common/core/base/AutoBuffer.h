#ifndef BASE_AUTO_BUFFER_H_
#define BASE_AUTO_BUFFER_H_

namespace zz {

class AutoBuffer {

  enum { SEEK_SET, SEEK_CUR, SEEK_END };

public:
  AutoBuffer(int capacity = 64) : capacity_(capacity) {
    buffer_ = static_cast<byte *>(malloc(capacity));
    cursor_ = buffer_;
    length_ = 0;

    memset(buffer_, 'A', capacity_); // Reset code buffer memory
  }

  void *Read(byte *ptr, size_t len) {
    FAIL_CHECK(len < length_);
    memcpy((void *)ptr, (void *)cursor_, len);
    return ptr;
  }
  void *Write(byte *ptr, size_t len) {
    Ensure(len);
    memcpy((void *)cursor_, (void *)ptr, len);
  }

  void Seek(size_t offset, int whence) {
    if (whence == SEEK_SET) {
      cursor_ = buffer_;
      return;
    } else if (whence == SEEK_CUR) {
      cursor_ = buffer_ + length_;
    } else if (whence == SEEK_END) {
      cursor_ = buffer_ + capacity_;
    }
  }

  size_t Length() const { return length_; }

  void *RawBuffer() { return buffer_; }

  void Ensure(size_t len) {
    if ((cursor_ + len) >= (buffer_ + capacity_)) {
      Grow(2 * capacity_);
    }
  }

  void *Grow(size_t new_capacity) {
    byte *buffer = (byte *)realloc(buffer_, new_capacity);
    FATAL_CHECK(!buffer);

    cursor_ = buffer + Length();
    buffer_ = buffer;

    memset(buffer_ + capacity_, 'A', new_capacity - capacity_); // Reset code buffer memory
    capacity_ = new_capacity;

    DLOG("[*] AutoBuffer Grow capacity %d\n", capacity_);
    return buffer_;
  }

private:
  // Backing store of the buffer
  byte *buffer_;

  // Pointer to the next location to be written.
  byte *cursor_;

  // Capacity in bytes of the backing store
  size_t capacity_;

  // Length of already bytes
  size_t length_;
};

} // namespace zz

#endif