#ifndef ZZ_BASE_CODE_BUFFER_H_
#define ZZ_BASE_CODE_BUFFER_H_

#include "vm_core/objects/objects.h"
#include "vm_core/macros.h"

#include <stdlib.h>
#include <string.h>

namespace zz {

class CodeBuffer {
public:
  CodeBuffer(int capacity = 64) : capacity_(capacity) {
    buffer_ = reinterpret_cast<byte *>(malloc(capacity));
    cursor_ = buffer_;
  }

  int32_t Load32(intptr_t position) {
    return *reinterpret_cast<int32_t *>(buffer_ + position);
  }

  void Store32(intptr_t position, int32_t value) {
    *reinterpret_cast<int32_t *>(buffer_ + position) = value;
  }

  void Emit(int32_t inst) {
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  void Emit64(int64_t inst) {
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  void EmitObject(const Object *object) {
  }

  size_t Size() const {
    return cursor_ - buffer_;
  }

  void *RawBuffer() {
    return buffer_;
  }

  void Grow(size_t new_capacity) {
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
