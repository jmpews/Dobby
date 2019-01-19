#include "arch/arm/ARMInterceptRouting.h"
#include "arch/arm/ARMInstructionRelocation.h"

#include "core/modules/assembler/assembler-arm.h"
#include "core/modules/codegen/codegen-arm.h"
#include "core/objects/code.h"

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

InterceptRouting *InterceptRouting::New(HookEntry *entry) {
  return reinterpret_cast<InterceptRouting *>(new ARMInterceptRouting(entry));
}

void ARMInterceptRouting::prepare_thumb() {
  uintptr_t src_address     = (uintptr_t)entry_->target_address;
  Interceptor *interceptor  = Interceptor::SharedInstance();
  MemoryRegion *region      = NULL;
  uword aligned_src_address = ThumbAlign(src_address);

  uint32_t inst = *(uint32_t *)aligned_src_address;
  if (interceptor->options().enable_arm_arm64_b_branch) {
    DLOG("%s", "[*] Enable b branch maybe cause crash, if crashed, please disable it.\n");
    // If the first instuction is thumb1(2 bytes), the first choice for use is thumb1 b-xxx, else use thumb2 b-xxx
    if (!is_thumb2(inst)) {
      // Try allocate a code cave for fast-forward-transfer-trampoline
      region = CodeChunk::AllocateCodeCave(aligned_src_address, THUMB1_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
      if (region) {
        DLOG("%s", "[*] Use Thumb1 B-xxx Branch\n");
        branch_type_  = Thumb1_B_Branch;
        relocate_size = 2;
      }
    }
    // Otherwith condisider the thumb2(4 bytes) b-xxx
    // Try allocate a code cave for fast-forward-transfer-trampoline
    if (!region) {
      region = CodeChunk::AllocateCodeCave(aligned_src_address, THUMB2_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
      if (region) {
        DLOG("%s", "[*] Use Thumb2 B-xxx Branch\n");
        branch_type_  = Thumb2_B_Branch;
        relocate_size = 4;
      } else
        DLOG("%s", "[!] Can't find any cove cave, change to ldr branch");
    }
  }

  if (region)
    fast_forward_region = region;
  else {
    DLOG("%s", "[*] Use Thumb2 Ldr Branch\n");
    branch_type_  = Thumb2_LDR_Branch;
    relocate_size = 8;
  }
}

void ARMInterceptRouting::prepare_arm() {
  uintptr_t src_address    = (uintptr_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();
  MemoryRegion *region     = NULL;
  if (interceptor->options().enable_arm_arm64_b_branch) {
    region = CodeChunk::AllocateCodeCave(src_address, ARM_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
    if (region) {
      DLOG("%s", "[*] Use ARM B-xxx Branch\n");
      branch_type_  = ARM_B_Branch;
      relocate_size = 4;
    } else {
      // Can't find any code cave, change to ldr branch
      DLOG("%s", "[!] Can't find any cove cave, change to ldr branch");
    }
  }
  if (region)
    fast_forward_region = region;
  else {
    DLOG("%s", "[*] Use ARM LDR Branch\n");
    branch_type_  = ARM_LDR_Branch;
    relocate_size = 8;
  }
}

// Determined if use B_Branch or LDR_Branch, and backup the origin instrutions
void ARMInterceptRouting::Prepare() {
  uintptr_t src_address = (uintptr_t)entry_->target_address;

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
  Code *code;
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

// Add pre_call(prologue) handler before running the origin function,
void ARMInterceptRouting::BuildPreCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *cte = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = cte->address;

  // build the fast forward trampoline jump to the normal routing(prologue_routing_dispatch).
  if (branch_type_ == ARM_B_Branch || branch_type_ == Thumb1_B_Branch || branch_type_ == Thumb2_B_Branch) {
    DLOG("%s", "[*] Fast forward to Pre-ClosureTrampoline\n");
    BuildFastForwardTrampoline();
  }

  DLOG("[*] create pre call closure trampoline to 'prologue_routing_dispatch' at %p\n", cte->address);
}

// Add post_call(epilogue) handler before `Return` of the origin function, as implementation is replace the origin `Return Address` of the function.
void ARMInterceptRouting::BuildPostCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)epilogue_routing_dispatch);
  entry_->epilogue_dispatch_bridge = closure_trampoline_entry->address;

  DLOG("[*] create post call closure trampoline to 'prologue_routing_dispatch' at %p\n",
       closure_trampoline_entry->address);
}

void ARMInterceptRouting::BuildReplaceRouting() {
  // build the fast forward trampoline jump to the normal routing(prologue_routing_dispatch).
  if (branch_type_ == ARM_B_Branch || branch_type_ == Thumb1_B_Branch || branch_type_ == Thumb2_B_Branch) {
    DLOG("%s", "[*] Fast forward to ReplaceCall\n");
    BuildFastForwardTrampoline();
  }
}

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
  } else if (entry_->type == kDynamicBinaryInstrumentation) {
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

// Add dbi_call handler before running the origin instructions
void ARMInterceptRouting::BuildDynamicBinaryInstrumentationRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = closure_trampoline_entry->address;

  if (branch_type_ == ARM_B_Branch || branch_type_ == Thumb1_B_Branch || branch_type_ == Thumb2_B_Branch) {
    BuildFastForwardTrampoline();
  }
  DLOG("create dynamic binary instrumentation call closure trampoline to 'prologue_dispatch_bridge' %p\n",
       closure_trampoline_entry->address);
}

// alias Active
void ARMInterceptRouting::Commit() { Active(); }

// active arm intercept routing
void ARMInterceptRouting::active_arm_intercept_routing() {
  TurboAssembler turbo_assembler_;
#undef _
#define _ turbo_assembler_.

  uintptr_t target_address = (uintptr_t)entry_->target_address;

  if (branch_type_ == ARM_B_Branch) {
    _ b((int32_t)entry_->fast_forward_trampoline - (int32_t)target_address - ARM_PC_OFFSET);
  } else {
    CodeGen codegen(&turbo_assembler_);
    // check if enable "fast forward trampoline"
    if (entry_->fast_forward_trampoline)
      codegen.LiteralLdrBranch((uint32_t)entry_->fast_forward_trampoline);
    else if (entry_->prologue_dispatch_bridge)
      codegen.LiteralLdrBranch((uint32_t)entry_->prologue_dispatch_bridge);
    else {
      if (entry_->type == kFunctionInlineHook)
        codegen.LiteralLdrBranch((uint32_t)entry_->replace_call);
    }
  }

  // Patch
  CodeChunk::MemoryOperationError err;
  err = CodeChunk::PatchCodeBuffer((void *)target_address, turbo_assembler_.GetCodeBuffer());
  CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
  Code::FinalizeFromAddress(target_address, turbo_assembler_.CodeSize());
}

// active thumb intercept routing
void ARMInterceptRouting::active_thumb_intercept_routing() {
  CustomThumbTurboAssembler thumb_turbo_assembler_;
#undef _
#define _ thumb_turbo_assembler_.

  uintptr_t target_address         = (uintptr_t)entry_->target_address;
  uintptr_t aligned_target_address = ThumbAlign(target_address);

  if (branch_type_ == ARMInterceptRouting::Thumb1_B_Branch) {
    _ t1_b((int32_t)entry_->fast_forward_trampoline - (int32_t)aligned_target_address - Thumb_PC_OFFSET);
  } else if (branch_type_ == ARMInterceptRouting::Thumb2_B_Branch) {
    _ t2_b((int32_t)entry_->fast_forward_trampoline - (int32_t)aligned_target_address - Thumb_PC_OFFSET);
  } else if (branch_type_ == ARMInterceptRouting::Thumb2_LDR_Branch) {
    // Check if needed pc align, (relative pc instructions needed 4 align)
    if (aligned_target_address % 4)
      _ t2_ldr(pc, MemOperand(pc, 2));
    else {
      _ t2_ldr(pc, MemOperand(pc, 0));
    }

    // check if enable "fast forward trampoline"
    if (entry_->fast_forward_trampoline)
      _ Emit((int32_t)entry_->fast_forward_trampoline);
    else if (entry_->prologue_dispatch_bridge)
      _ Emit((int32_t)entry_->prologue_dispatch_bridge);
    else {
      if (entry_->type == kFunctionInlineHook)
        _ Emit((int32_t)entry_->replace_call);
    }
  } else {
    UNREACHABLE();
  }
  // Patch
  CodeChunk::MemoryOperationError err;
  err = CodeChunk::PatchCodeBuffer((void *)aligned_target_address, thumb_turbo_assembler_.GetCodeBuffer());
  CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
  Code::FinalizeFromAddress(aligned_target_address, thumb_turbo_assembler_.CodeSize());
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void ARMInterceptRouting::Active() {
  if (execute_state_ == ARMExecuteState) {
    DLOG("[*] Active the routing at %p\n", entry_->target_address);
    active_arm_intercept_routing();
  } else {
    DLOG("[*] Active the routing at %p\n", entry_->target_address);
    active_thumb_intercept_routing();
  }
}
