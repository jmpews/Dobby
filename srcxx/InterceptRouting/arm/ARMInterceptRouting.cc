#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "ExecMemory/ExecutableMemoryArena.h"

#include "InstructionRelocation/arm/ARMInstructionRelocation.h"
#include "InterceptRouting/arm/ARMInterceptRouting.h"

using namespace zz::arm;

// arm branch meta info
#define ARM_TINY_REDIRECT_SIZE 4
#define ARM_B_XXX_RANGE (1 << 25) // signed == (1 << (24-1))<< 2
#define ARM_FULL_REDIRECT_SIZE 8

// thumb branch meta info
#define THUMB1_TINY_REDIRECT_SIZE 2
#define THUMB2_TINY_REDIRECT_SIZE 4
#define THUMB1_B_XXX_RANGE (1 << 10) // signed
#define THUMB2_B_XXX_RANGE (1 << 23) // signed
#define THUMB_FULL_REDIRECT_SIZE 8

static bool is_thumb2(uint32_t inst) {
  uint16_t inst1, inst2;
  inst1 = inst & 0x0000ffff;
  inst2 = (inst & 0xffff0000) >> 16;
  // refer: Top level T32 instruction set encoding
  uint32_t op0 = bits(inst1, 13, 15);
  uint32_t op1 = bits(inst1, 11, 12);

  if (op0 == 0b111 && op1 != 0b00) {
    return true;
  }
  return false;
}

#if 0
InterceptRouting *InterceptRouting::New(HookEntry *entry) {
  return reinterpret_cast<InterceptRouting *>(new ARMInterceptRouting(entry));
}
#endif

void InterceptRouting::prepare_thumb() {
  uint32_t src_address     = (uint32_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();

  branch_type_  = Thumb2_LDR_Branch;
  relocate_size = 8;
}

void InterceptRouting::prepare_arm() {
  uintptr_t src_address    = (uintptr_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();

  branch_type_  = ARM_LDR_Branch;
  relocate_size = 8;
}

// Determined if use B_Branch or LDR_Branch, and backup the origin instrutions
void InterceptRouting::Prepare() {
  uint32_t src_address = (uint32_t)entry_->target_address;

  // set instruction running state
  execute_state_ = ARMExecuteState;
  if (src_address % 2) {
    execute_state_ = ThumbExecuteState;
  }

  // Determined which branch_type_, and corrreponding trampoline size
  if (execute_state_ == ThumbExecuteState) {
    prepare_thumb();
  } else {
    prepare_arm();
  }

  // Gen the relocated code
  AssemblyCode *code;
  code                              = GenRelocateCode(src_address, &relocate_size);
  entry_->relocated_origin_function = (void *)code->raw_instruction_start();
  // If Thumb Execute, code snippet address should be odd.
  if (execute_state_ == ThumbExecuteState) {
    entry_->relocated_origin_function = (void *)((uint32_t)entry_->relocated_origin_function + 1);
  }
  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // backup original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// active arm intercept routing
void InterceptRouting::active_arm_intercept_routing() {
  TurboAssembler turbo_assembler_;
#undef _
#define _ turbo_assembler_.

  uint32_t target_address = (uint32_t)entry_->target_address;
  uint32_t branch_address = (uint32_t)GetTrampolineTarget();

  CodeGen codegen(&turbo_assembler_);
  codegen.LiteralLdrBranch(branch_address);

  // Patch
  MemoryOperationError err;
  err = CodePatch((void *)target_address, turbo_assembler_.GetCodeBuffer()->getRawBuffer(),
                  turbo_assembler_.GetCodeBuffer()->getSize());
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, turbo_assembler_.GetCodeBuffer()->getSize());
}

// active thumb intercept routing
void InterceptRouting::active_thumb_intercept_routing() {
  CustomThumbTurboAssembler thumb_turbo_assembler_;
#undef _
#define _ thumb_turbo_assembler_.

  uintptr_t target_address         = (uintptr_t)entry_->target_address;
  uintptr_t aligned_target_address = ThumbAlign(target_address);
  uint32_t branch_address          = (uint32_t)GetTrampolineTarget();

  // Check if needed pc align, (relative pc instructions needed 4 align)
  if (aligned_target_address % 4)
    _ t2_ldr(pc, MemOperand(pc, 2));
  else {
    _ t2_ldr(pc, MemOperand(pc, 0));
  }
  _ EmitAddress(branch_address);

  // Patch
  MemoryOperationError err;
  err = CodePatch((void *)target_address, thumb_turbo_assembler_.GetCodeBuffer()->getRawBuffer(),
                  thumb_turbo_assembler_.GetCodeBuffer()->getSize());
  CHECK_EQ(err, kMemoryOperationSuccess);
  AssemblyCode::FinalizeFromAddress(target_address, thumb_turbo_assembler_.GetCodeBuffer()->getSize());
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void InterceptRouting::Active() {
  if (execute_state_ == ARMExecuteState) {
    DLOG("[*] Active the routing at %p\n", entry_->target_address);
    active_arm_intercept_routing();
  } else {
    DLOG("[*] Active the routing at %p\n", entry_->target_address);
    active_thumb_intercept_routing();
  }
}
