#include "stdcxx/LiteMutableBuffer.h"

bool LiteMutableBuffer::initWithCapacity(int in_capacity) {
  this->buffer_ = (byte *)LiteMemOpt::alloc(in_capacity);
  assert(this->buffer_);

  this->cursor_   = buffer_;
  this->capacity_ = in_capacity;
  return true;
}

int LiteMutableBuffer::ensureCapacity(int new_capacity) {
  byte *new_buffer;

  if (new_capacity <= this->capacity_)
    return this->capacity_;

#undef CAPACITY_STEP
#define CAPACITY_STEP 64
  new_capacity = (int)ALIGN(new_capacity + CAPACITY_STEP, CAPACITY_STEP);

  new_buffer = (byte *)LiteMemOpt::alloc(new_capacity);
  assert(new_buffer);
  _memset(new_buffer, 'A', new_capacity);

  int offset = (int)(this->cursor_ - this->buffer_);
  assert(offset == this->getSize());
  _memcpy(new_buffer, this->buffer_, offset);

  // free the origin
  LiteMemOpt::free(this->buffer_, this->capacity_);

  this->cursor_   = new_buffer + offset;
  this->buffer_   = new_buffer;
  this->capacity_ = new_capacity;

  return new_capacity;
}

void LiteMutableBuffer::release() {
  LiteMemOpt::free(this->buffer_, this->capacity_);
}
