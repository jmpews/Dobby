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

#undef CAPACITY_STEP
#define CAPACITY_STEP 64
  final_capacity = (int)ALIGN(new_capacity + CAPACITY_STEP, CAPACITY_STEP);

  new_buffer = (byte *)LiteMemOpt::alloc(final_capacity);
  // clear with the mark 'A'
  _memset(new_buffer, 'A', final_capacity);

  if (new_buffer) {
    int offset = (int)(cursor_ - buffer_);
    ASSERT(offset == getSize());

    // copy the origin content
    _memcpy(new_buffer, buffer_, offset);

    // free the origin
    LiteMemOpt::free(buffer_, capacity_);

    cursor_   = new_buffer + offset;
    buffer_   = new_buffer;
    capacity_ = new_capacity;
  }

  return capacity_;
}
