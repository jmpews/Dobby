#include "stdcxx/LiteMutableBuffer.h"

bool LiteMutableBuffer::initWithCapacity(int in_capacity) {
  buffer_ = (byte *)LiteMemOpt::alloc(in_capacity);
  if (!buffer_) {
    return false;
  }

  cursor_   = buffer_;
  capacity_ = in_capacity;
  return true;
}

int LiteMutableBuffer::ensureCapacity(int new_capacity) {
  byte *new_buffer;
  unsigned int final_capacity;

  if (new_capacity <= capacity_)
    return capacity_;
  final_capacity = (int)ALIGN(new_capacity, 8);

  new_buffer = (byte *)LiteMemOpt::alloc(final_capacity);

  if (new_buffer) {
    cursor_   = new_buffer + getSize();
    buffer_   = new_buffer;
    capacity_ = new_capacity;
  }

  return capacity_;
}
