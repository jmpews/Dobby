#ifndef ZZ_BASE_CODE_BUFFER_H_
#define ZZ_BASE_CODE_BUFFER_H_

#include "vm_core/objects/objects.h"
#include "vm_core/macros.h"
#include "vm_core/globals.h"
#include "vm_core/logging.h"
#include "vm_core/check_logging.h"

#include <stdlib.h>
#include <string.h>

namespace zz {

class CodeBuffer {
public:
  CodeBuffer(int capacity = 64) : capacity_(capacity) {
    buffer_ = reinterpret_cast<byte *>(malloc(capacity));
    cursor_ = buffer_;
    // reset code buffer memory
    memset(buffer_, 'A', capacity_);
  }

  // =====

  int32_t Load32(intptr_t position) { return *reinterpret_cast<int32_t *>(buffer_ + position); }

  template <typename T> T Load(intptr_t position) { return *reinterpret_cast<T *>(buffer_ + position); }

  void Store32(intptr_t position, int32_t value) { *reinterpret_cast<int32_t *>(buffer_ + position) = value; }

  template <typename T> void Store(intptr_t position, T value) { *reinterpret_cast<T *>(buffer_ + position) = value; }

  // =====

  void Emit(int32_t inst) {
    Ensure(sizeof(int32_t));
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  void Emit64(int64_t inst) {
    Ensure(sizeof(int64_t));
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  template <typename T> void Emit(T value) {
    Ensure(sizeof(T));
    *reinterpret_cast<T *>(cursor_) = value;
    cursor_ += sizeof(T);
  }

  void EmitObject(const Object *object) {}

  // =====

  size_t Size() const { return cursor_ - buffer_; }

  void *RawBuffer() { return buffer_; }

  // =====

  void Ensure(int size) {
    if ((cursor_ + size) >= (buffer_ + capacity_)) {
      Grow(2 * capacity_);
    }
  }

  void Grow(size_t new_capacity) {
    byte *buffer = (byte *)realloc(buffer_, new_capacity);
    cursor_      = buffer + Size();
    buffer_      = buffer;
    // reset code buffer memory
    memset(buffer_ + capacity_, 'A', new_capacity - capacity_);
    capacity_ = new_capacity;
    DLOG("[*] Codebuffer Grow at %p with capacity %d\n", buffer_, capacity_);
  }

private:
  // Backing store of the buffer
  byte *buffer_;
  // Pointer to the next location to be written.
  byte *cursor_;
  // Capacity in bytes of the backing store
  size_t capacity_;
};

} // namespace zz

#endif
