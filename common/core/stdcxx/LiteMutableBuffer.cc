#include "stdcxx/LiteMutableBuffer.h"

bool Lie

    size_t
    getLength() const {
  return length_;
}

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

  DLOG("[*] AutoMutableBuffer Grow capacity %d\n", capacity_);
  return buffer_;
}