#include "xnucxx/LiteMutableBuffer.h"

bool LiteMutableBuffer::initWithCapacity(uint32_t in_capacity) {
  if (in_capacity <= 0)
    return false;
  this->buffer_ = (uint8_t *)LiteMemOpt::alloc(in_capacity);
  assert(this->buffer_);

  this->buffer_cursor_   = buffer_;
  this->buffer_capacity_ = in_capacity;
  return true;
}

uint32_t LiteMutableBuffer::ensureCapacity(uint32_t new_capacity) {
  uint8_t *new_buffer;

  if (new_capacity <= this->buffer_capacity_)
    return this->buffer_capacity_;

#undef CAPACITY_STEP
#define CAPACITY_STEP 64
  new_capacity = (uint32_t)ALIGN(new_capacity + CAPACITY_STEP, CAPACITY_STEP);

  new_buffer = (uint8_t *)LiteMemOpt::alloc(new_capacity);
  assert(new_buffer);
  _memset(new_buffer, 'A', new_capacity);

  uint32_t offset = (uint32_t)(this->buffer_cursor_ - this->buffer_);
  assert(offset == this->getSize());
  _memcpy(new_buffer, this->buffer_, offset);

  // free the origin
  LiteMemOpt::free(this->buffer_, this->buffer_capacity_);

  this->buffer_cursor_   = new_buffer + offset;
  this->buffer_          = new_buffer;
  this->buffer_capacity_ = new_capacity;

  return new_capacity;
}

#if 0
LiteMutableBuffer *LiteMutableBuffer::copy() {
  LiteMutableBuffer *result = new LiteMutableBuffer(this->buffer_capacity_);
}
#endif

void LiteMutableBuffer::release() {
  if (this->buffer_ != NULL) {
    LiteMemOpt::free(this->buffer_, this->buffer_capacity_);
    this->buffer_ = NULL;
    return;
  }

  ERROR_LOG("double free occured");
}
