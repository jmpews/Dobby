#ifndef CODE_BUFFER_ARM64_H_
#define CODE_BUFFER_ARM64_H_

#include "CodeBufferBase.h"

typedef int32_t arm64_inst_t;

class CodeBuffer : public CodeBufferBase {

public:
  CodeBuffer() : CodeBufferBase() {
  }

  CodeBuffer(int size) : CodeBufferBase(size) {
  }

public:
  arm64_inst_t LoadInst(int offset);

  void RewriteInst(int offset, arm64_inst_t inst);

  void EmitInst(arm64_inst_t inst);

  void Emit64(int64_t data);
};

#endif
