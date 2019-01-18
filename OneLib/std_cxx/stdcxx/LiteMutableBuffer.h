#ifndef LITE_MUTABLE_BUFFER_H_
#define LITE_MUTABLE_BUFFER_H_

#include "stdcxx/LiteObject.h"

class LiteMutableBuffer : public LiteObject {
protected:
  // Backing store of the buffer
  byte *buffer_;

  // Pointer to the next location to be written.
  byte *cursor_;

  // Capacity in bytes of the backing store
  size_t capacity_;

  // Length of already bytes
  size_t size_;

public:
  virtual size_t ensureCapacity(size_t newCapacity);

  virtual bool initWithCapacity(size_t capacity);

  virtual inline size_t getSize() { return size_; }

  virtual inline size_t getCapacity() { return capacity_; }

  virtual inline void *getCursor() { return cursor_; }

  virtual inline void *getRawBuffer() { return buffer_; }
};

#endif