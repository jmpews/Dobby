#ifndef LITE_MUTABLE_BUFFER_H
#define LITE_MUTABLE_BUFFER_H

#include "xnucxx/LiteObject.h"

class LiteMutableBuffer : public LiteObject {
protected:
  // Backing store of the buffer
  uint8_t *buffer_;

  // Pointer to the next location to be written.
  uint8_t *buffer_cursor_;

  // Capacity in bytes of the backing store
  uint32_t buffer_capacity_;

public:
  LiteMutableBuffer() {
    initWithCapacity(8);
  }

  LiteMutableBuffer(uint32_t size) {
    initWithCapacity(size);
  }

  ~LiteMutableBuffer() {
    this->release();
  }

  virtual void release() override;

  virtual uint32_t ensureCapacity(uint32_t newCapacity);

  virtual bool initWithCapacity(uint32_t capacity = 8);

  virtual inline uint32_t getSize() {
    return (uint32_t)(buffer_cursor_ - buffer_);
  }

  virtual inline uint32_t getCapacity() {
    return buffer_capacity_;
  }

  virtual inline void *getCursor() {
    return buffer_cursor_;
  }

  virtual inline void *getRawBuffer() {
    return buffer_;
  }
};

#endif
