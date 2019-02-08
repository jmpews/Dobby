#ifndef ARM64_CODE_BUFFER_H_
#define ARM64_CODE_BUFFER_H_

#include "CodeBufferBase.h"

typedef int32_t arm64_inst_t;

class CodeBuffer : public LiteMutableBuffer {

public:
  arm64_inst_t LoadInst(int offset);

  void RewriteInst(int offset, arm64_inst_t inst);

  void EmitInst(arm64_inst_t inst);

  void Emit64(int64_t data);
};

#endif