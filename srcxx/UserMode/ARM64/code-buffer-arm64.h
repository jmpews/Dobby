#ifndef ZZ_CODE_BUFFER_H_
#define ZZ_CODE_BUFFER_H_

#include "CodeBufferBase.h"

typedef arm64_inst_t int32_t;

class CodeBuffer : LiteMutableBuffer {

public:
  arm64_inst_t LoadInst(int offset);

  void RewriteInst(int offset, arm64_inst_t inst);

  void EmitInst(int offset, arm64_inst_t inst);

  void Emit64(int64_t data);
};

#endif