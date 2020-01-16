
#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#include "InstructionRelocation/arm/ARMInstructionRelocation.h"

using namespace zz::arm;

CodeBuffer *gen_arm_trampoline(void *from, void *to) {
  TurboAssembler turbo_assembler_(from);
#undef _
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch((uint32_t)to);

  return turbo_assembler_.GetCodeBuffer()->copy();
}

CodeBuffer *gen_thumb_trampoline(void *from, void *to) {
  CustomThumbTurboAssembler thumb_turbo_assembler_(from);
#undef _
#define _ thumb_turbo_assembler_.

  // Check if needed pc align, (relative pc instructions needed 4 align)
  from = (void *)ALIGN(from, 2);
  if ((uint32_t)from % 4)
    _ t2_ldr(pc, MemOperand(pc, 2));
  else {
    _ t2_ldr(pc, MemOperand(pc, 0));
  }
  _ EmitAddress((uint32_t)to);

  return thumb_turbo_assembler_.GetCodeBuffer()->copy();
}

CodeBufferBase *GenTrampoline(void *from, void *to) {
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

  ExecuteState execute_state_;

  // set instruction running state
  execute_state_ = ARMExecuteState;
  if ((addr_t)from % 2) {
    execute_state_ = ThumbExecuteState;
  }

  if (execute_state_ == ARMExecuteState) {
    return gen_arm_trampoline(from, to);
  } else {
    return gen_thumb_trampoline(from, to);
  }
  return 0;
}