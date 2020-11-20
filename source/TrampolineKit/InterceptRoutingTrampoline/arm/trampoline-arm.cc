#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_ARM)

#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#include "InstructionRelocation/arm/ARMInstructionRelocation.h"

#include "InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/NearMemoryArena.h"
#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz::arm;

static CodeBufferBase *generate_arm_trampoline(addr32_t from, addr32_t to) {
  TurboAssembler turbo_assembler_((void *)from);
#define _ turbo_assembler_.

  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(to);

  return turbo_assembler_.GetCodeBuffer()->Copy();
}

CodeBufferBase *generate_thumb_trampoline(addr32_t from, addr32_t to) {
  ThumbTurboAssembler thumb_turbo_assembler_((void *)from);
#undef _
#define _ thumb_turbo_assembler_.

  _ AlignThumbNop();
  _ t2_ldr(pc, MemOperand(pc, 0));
  _ EmitAddress(to);

  return thumb_turbo_assembler_.GetCodeBuffer()->Copy();
}

CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
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
    // Check if needed pc align, (relative pc instructions needed 4 align)
    from = ALIGN(from, 2);
    return generate_thumb_trampoline(from, to);
  }
  return NULL;
}

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  return NULL;
}

#endif