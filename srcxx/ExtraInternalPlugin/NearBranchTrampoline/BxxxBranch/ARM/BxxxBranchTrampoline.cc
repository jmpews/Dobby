//
// Created by jmpews on 2019/1/20.
//

#include "BxxxBranchTrampoline.h"

static Code *build_thumb_fast_forward_trampoline(uintptr_t address, MemoryRegion *region) {
  CustomThumbTurboAssembler thumb_turbo_assembler_;
#define _ thumb_turbo_assembler_.

  _ t2_ldr(pc, MemOperand(pc, 0));
  _ Emit((int32_t)address);

  // Patch
  CodeChunk::MemoryOperationError err;
  err = CodeChunk::PatchCodeBuffer((void *)region->pointer(), thumb_turbo_assembler_.GetCodeBuffer());
  CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
  Code *code = Code::FinalizeFromAddress((uintptr_t)region->pointer(), thumb_turbo_assembler_.CodeSize());
  return code;
}

static Code *build_arm_fast_forward_trampoline(uintptr_t address, MemoryRegion *region) {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(address);

  // Patch
  CodeChunk::MemoryOperationError err;
  err = CodeChunk::PatchCodeBuffer((void *)region->pointer(), turbo_assembler_.GetCodeBuffer());
  CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
  Code *code = Code::FinalizeFromAddress((uintptr_t)region->pointer(), turbo_assembler_.CodeSize());
  return code;
}

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
void ARMInterceptRouting::BuildFastForwardTrampoline() {
  uint32_t forward_address;
  Code *code;
  if (entry_->type == kFunctionInlineHook) {
    forward_address = (uintptr_t)entry_->replace_call;
  } else if (entry_->type == kDynamicBinaryInstrument) {
    forward_address = (uintptr_t)entry_->prologue_dispatch_bridge;
  } else if (entry_->type == kFunctionWrapper) {
    forward_address = (uintptr_t)entry_->prologue_dispatch_bridge;
  } else {
    UNREACHABLE();
    exit(-1);
  }
  if (execute_state_ == ThumbExecuteState) {
    code = build_thumb_fast_forward_trampoline(forward_address, fast_forward_region);
  } else {
    code = build_arm_fast_forward_trampoline(forward_address, fast_forward_region);
  }
  entry_->fast_forward_trampoline = (void *)code->raw_instruction_start();
}
