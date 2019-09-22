#ifndef X64_CODE_BUFFER_H_
#define X64_CODE_BUFFER_H_

#include "./CodeBufferBase.h"

class CodeBuffer : public CodeBufferBase {
public:
  CodeBuffer() : CodeBufferBase() {
  }

  CodeBuffer(int size) : CodeBufferBase(size) {
  }
};

#endif