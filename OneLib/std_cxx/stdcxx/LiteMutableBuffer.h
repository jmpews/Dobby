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
  size_t length_;

public:
  virtual size_t getLength();

  virtual size_t getCapacity();

  virtual size_t ensureCapacity(size_t newCapacity);

  virtual bool initWithCapacity(size_t capacity);

  virtual void *getCursor();
};

#endif