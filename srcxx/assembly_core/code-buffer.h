#ifndef ZZ_BASE_CODE_BUFFER_H
#define ZZ_BASE_CODE_BUFFER_H

#include "assembly_core/globals.h"
#include "base_core/objects/objects.h"

class CodeBuffer {
public:
  CodeBuffer(int capacity) : capacity_(capacity) {
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