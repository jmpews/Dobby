
#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#include "InstructionRelocation/arm/ARMInstructionRelocation.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/NearExecutableMemoryArena.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz::arm;

static CodeBufferBase *generate_arm_trampoline(void *from, void *to) {
  TurboAssembler turbo_assembler_(from);
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch((uint32_t)to);

  return turbo_assembler_.GetCodeBuffer()->copy();
}

CodeBufferBase *generate_thumb_trampoline(void *from, void *to) {
  ThumbTurboAssembler thumb_turbo_assembler_(from);
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

CodeBufferBase *GenerateNormalTrampolineBuffer(void *from, void *to) {
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

  // set instruction running state
  ExecuteState execute_state_;
  execute_state_ = ARMExecuteState;
  if ((addr_t)from % 2) {
    execute_state_ = ThumbExecuteState;
  }

  if (execute_state_ == ARMExecuteState) {
    return generate_arm_trampoline(from, to);
  } else {
    return generate_thumb_trampoline(from, to);
  }
  return NULL;
}

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  return NULL;
}