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
  int capacity_;

  // Length of already bytes
  // int size_;

public:
  virtual int ensureCapacity(int newCapacity);

  virtual bool initWithCapacity(int capacity = 8);

  virtual inline int getSize() {
    return (int)(cursor_ - buffer_);
  }

  virtual inline int getCapacity() {
    return capacity_;
  }

  virtual inline void *getCursor() {
    return cursor_;
  }

  virtual inline void *getRawBuffer() {
    return buffer_;
  }
};

#endif
