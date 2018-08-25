#ifndef ZZ_BASE_CODE_BUFFER_H
#define ZZ_BASE_CODE_BUFFER_H

#include "src/globals.h"
#include "src/base/objects/objects.h"

class CodeBuffer {
public:
  void Emit(int32_t inst) {
  }

  void EmitObject(const Object *object) {
  }

  void FinalizeInstructions() {
  }

private:
  byte *buffer_;
};

#endif