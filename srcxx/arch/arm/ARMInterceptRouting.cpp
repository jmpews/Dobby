#include "arch/arm/ARMInterceptRouting.h"
#include "arch/arm/ARMInstructionRelocation.h"
#include "arch/arm/ARMInstructionRelocation.h"

#include "vm_core/modules/assembler/assembler-arm.h"
#include "vm_core/modules/codegen/codegen-arm.h"
#include "vm_core/objects/code.h"

#include "vm_core_extra/code-page-chunk.h"
#include "vm_core_extra/custom-code.h"

using namespace zz::arm;

// arm branch meta info
#define ARM_TINY_REDIRECT_SIZE 4
#define ARM_B_XXX_RANGE (1 << 25) // signed
#define ARM_FULL_REDIRECT_SIZE 8

// thumb branch meta info
#define THUMB1_TINY_REDIRECT_SIZE 2
#define THUMB2_TINY_REDIRECT_SIZE 4
#define THUMB1_B_XXX_RANGE (1 << 11) // signed
#define THUMB2_B_XXX_RANGE (1 << 25) // signed
#define THUMB_FULL_REDIRECT_SIZE 8

static bool is_thumb2(uint32_t inst) {
  uint16_t inst1, inst2;
  inst1        = inst & 0x0000ffff;
  inst2        = (inst & 0xffff0000) >> 16;
  uint32_t op0 = bits(inst1, 11, 12);

  if (op0 == 0b111) {
    return true;
  }
  return false;
}

InterceptRouting *InterceptRouting::New(HookEntry *entry) {
  return reinterpret_cast<InterceptRouting *>(new ARMInterceptRouting(entry));
}

// Determined if use B_Branch or LDR_Branch, and backup the origin instrutions
void ARMInterceptRouting::Prepare() {
  uintptr_t src_pc         = (uintptr_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();
  int need_relocated_size  = 0;

  // set instruction running state
  execute_state_ = ARMExecuteState;
  if (src_pc % 2) {
    execute_state_ = ThumbExecuteState;
  }

  if (execute_state_ == ThumbExecuteState) {
    MemoryRegion *region = NULL;
    uint32_t inst        = *(uint32_t *)src_pc;
    if (interceptor->options().enable_b_branch) {
      DLOG("%s", "[*] Enable b branch maybe cause crash, if crashed, please disable it.\n");
      do {
        // If the first instuction is thumb1(2 bytes), the first choice for use is thumb1 b-xxx, else use thumb2 b-xxx
        if (!is_thumb2(inst)) {
          // Try allocate a code cave for fast-forward-transfer-trampoline
          region = CodeChunk::AllocateCodeCave(src_pc, THUMB1_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
          if (region) {
            DLOG("%s", "[*] Use Thumb1 B-xxx Branch\n");
            branch_type_        = Thumb1_B_Branch;
            need_relocated_size = 2;
            break;
          }
        }
        // Otherwith condisider the thumb2(4 bytes) b-xxx
        // Try allocate a code cave for fast-forward-transfer-trampoline
        region = CodeChunk::AllocateCodeCave(src_pc, THUMB2_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
        if (region) {
          DLOG("%s", "[*] Use Thumb2 B-xxx Branch\n");
          branch_type_        = Thumb2_B_Branch;
          need_relocated_size = 4;
          break;
        }
        DLOG("%s", "[!] Can't find any cove cave, change to ldr branch");
      } while (0);
    }

    if (region)
      delete region;
    else {
      DLOG("%s", "[*] Use Thumb2 Ldr Branch\n");
      branch_type_        = Thumb2_LDR_Branch;
      need_relocated_size = 8;
    }
  } else {
    MemoryRegion *region;
    if (interceptor->options().enable_b_branch) {
      region = CodeChunk::AllocateCodeCave(src_pc, ARM_B_XXX_RANGE, ARM_FULL_REDIRECT_SIZE);
      if (region) {
        DLOG("%s", "[*] Use ARM B-xxx Branch\n");
        branch_type_        = ARM_B_Branch;
        need_relocated_size = 8;
      } else {
        // Can't find any code cave, change to ldr branch
        DLOG("%s", "[!] Can't find any cove cave, change to ldr branch");
      }
    }
    if (region)
      delete region;
    else {
      DLOG("%s", "[*] Use ARM B-xxx Branch\n");
      delete region;
      branch_type_ = ARM_LDR_Branch;
    }
  }

  // Gen the relocated code
  Code *code;
  code                              = GenRelocateCode(src_pc, need_relocated_size);
  entry_->relocated_origin_function = (void *)code->raw_instruction_start();
  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // save original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, need_relocated_size);
  entry_->origin_instructions.size    = need_relocated_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// Add pre_call(prologue) handler before running the origin function,
void ARMInterceptRouting::BuildPreCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *cte = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = cte->address;

  // build the fast forward trampoline jump to the normal routing(prologue_routing_dispatch).
  if (branch_type_ == ARM_B_Branch || branch_type_ == Thumb1_B_Branch || branch_type_ == Thumb2_B_Branch)
    BuildFastForwardTrampoline();

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

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
void ARMInterceptRouting::BuildFastForwardTrampoline() {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  if (entry_->type == kFunctionInlineHook) {
    codegen.LiteralLdrBranch((uintptr_t)entry_->replace_call);
    DLOG("create fast forward trampoline to 'replace_call' %p\n", entry_->replace_call);
  } else if (entry_->type == kDynamicBinaryInstrumentation) {
    codegen.LiteralLdrBranch((uintptr_t)entry_->prologue_dispatch_bridge);
    DLOG("create fast forward trampoline to 'prologue_dispatch_bridge' %p\n", entry_->prologue_dispatch_bridge);
  } else if (entry_->type == kFunctionWrapper) {
    DLOG("create fast forward trampoline to 'prologue_dispatch_bridge' %p\n", entry_->prologue_dispatch_bridge);
    codegen.LiteralLdrBranch((uintptr_t)entry_->prologue_dispatch_bridge);
  }

  AssemblerCode *code             = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  entry_->fast_forward_trampoline = (void *)code->raw_instruction_start();
}

// Add dbi_call handler before running the origin instructions
void ARMInterceptRouting::BuildDynamicBinaryInstrumentationRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = closure_trampoline_entry->address;

  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->options().enable_b_branch) {
    BuildFastForwardTrampoline();
  }
  DLOG("create dynamic binary instrumentation call closure trampoline to 'prologue_dispatch_bridge' %p\n",
       closure_trampoline_entry->address);
}

// alias Active
void ARMInterceptRouting::Commit() {
  Active();
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void ARMInterceptRouting::Active() {
  uintptr_t target_address = (uintptr_t)entry_->target_address;

  if (execute_state_ == ARMExecuteState) {
    TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
    if (branch_type_ == ARM_B_Branch) {
      _ b((int32_t)entry_->fast_forward_trampoline - (int32_t)target_address);
    } else {
      CodeGen codegen(&turbo_assembler_);
      codegen.LiteralLdrBranch((uint32_t)entry_->prologue_dispatch_bridge);
    }

    // Patch
    CodeChunk::MemoryOperationError err;
    err = CodeChunk::PatchCodeBuffer((void *)target_address, turbo_assembler_.GetCodeBuffer());
    CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
    Code::FinalizeFromAddress(target_address, turbo_assembler_.CodeSize());
  } else {
    CustomThumbTurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
    if (branch_type_ == Thumb1_B_Branch) {
      _ t1_b((int32_t)entry_->fast_forward_trampoline - (int32_t)target_address);
    } else if (branch_type_ == Thumb2_B_Branch) {
      _ t2_b((int32_t)entry_->fast_forward_trampoline - (int32_t)target_address);
    } else if (branch_type_ == Thumb2_LDR_Branch) {
      // Check if needed pc align, (relative pc needed 4 align)
      if (target_address % 4)
        _ t2_ldr(pc, MemOperand(pc, -2));
      else {
        _ t2_ldr(pc, MemOperand(pc, -4));
        _ Emit((int32_t)entry_->prologue_dispatch_bridge);
      }
    } else {
      UNREACHABLE();
    }
    // Patch
    CodeChunk::MemoryOperationError err;
    err = CodeChunk::PatchCodeBuffer((void *)target_address, turbo_assembler_.GetCodeBuffer());
    CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
    Code::FinalizeFromAddress(target_address, turbo_assembler_.CodeSize());
  }
  DLOG("[*] Active the routing at %p\n", entry_->target_address);
}
