#ifndef ZZ_BASE_CODE_BUFFER_H_
#define ZZ_BASE_CODE_BUFFER_H_

#include "vm_core/objects/objects.h"
#include "vm_core/globals.h"


class CodeBuffer {
public:
  CodeBuffer(int capacity = 64) : capacity_(capacity) {
    buffer_ = reinterpret_cast<byte *>(malloc(capacity));
  }

  void Emit(int32_t inst) {
  }

  void EmitObject(const Object *object) {
  }

  void FinalizeInstructions() {
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

#endif