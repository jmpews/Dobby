#ifndef ZZ_CODE_BUFFER_H_
#define ZZ_CODE_BUFFER_H_

#include "CodeBuffer.h"

typedef arm_inst_t int32_t;
typedef thumb_inst_t int32_t;

class CodeBufferARM : CodeBuffer {
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

public:
  arm_inst_t LoadARMInst(int offset);

  thumb_inst_t LoadThumbInst(int offset);

  void RewriteARMInst(int offset, arm_inst_t inst);

  void RewriteThumbInst(int offset, thumb_inst_t inst);

  void EmitARMInst(int offset, arm_inst_t inst);

  void EmitThumbInst(int offset, thumb_inst_t inst);

  void Emit32(int32_t data);
};

#endif