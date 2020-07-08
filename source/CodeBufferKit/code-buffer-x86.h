#ifndef CODE_BUFFER_X86_H
#define CODE_BUFFER_X86_H

#include "./CodeBufferBase.h"

class CodeBuffer : public CodeBufferBase {
public:
  CodeBuffer() : CodeBufferBase() {
  }

  CodeBuffer(int size) : CodeBufferBase(size) {
  }
};

#endif