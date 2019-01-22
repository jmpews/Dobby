#ifndef ARM_CODE_BUFFER_H_
#define ARM_CODE_BUFFER_H_

#include "CodeBuffer.h"

typedef int32_t arm_inst_t;
typedef int32_t thumb_inst_t;

class CodeBufferARM : public CodeBuffer {
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