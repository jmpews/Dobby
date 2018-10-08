#include "AssemblyClosureTrampoline.h"
#include "intercept_routing_handler.h"
#include "arch/arm64/ARM64InstructionRelocation.h"
#include "arch/arm64/ARM64InterceptRouting.h"

#include "vm_core/modules/assembler/assembler-arm64.h"
#include "vm_core/modules/codegen/codegen-arm64.h"
#include "vm_core/objects/code.h"

#include "vm_core_extra/custom-code.h"
#include "vm_core_extra/code-page-chunk.h"

using namespace zz::arm64;

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_B_XXX_RANGE (1 << 25) // signed
#define ARM64_FULL_REDIRECT_SIZE 16

InterceptRouting *InterceptRouting::New(HookEntry *entry) {
  return reinterpret_cast<InterceptRouting *>(new ARM64InterceptRouting(entry));
}

// Determined if use B_Branch or LDR_Branch, and backup the origin instrutions
void ARM64InterceptRouting::Prepare() {
  uint64_t src_pc          = (uint64_t)entry_->target_address;
  Interceptor *interceptor = Interceptor::SharedInstance();
  int relocate_size        = 0;
  MemoryRegion *region     = NULL;

  if (interceptor->options().enable_b_branch) {
    DLOG("%s", "[*] Enable b branch maybe cause crash, if crashed, please disable it.\n");
    DLOG("%s", "[*] Use ARM64 B-xxx Branch.\n");
    region = CodeChunk::AllocateCodeCave(src_pc, ARM64_B_XXX_RANGE, ARM64_TINY_REDIRECT_SIZE);
    if (region) {
      relocate_size = ARM64_TINY_REDIRECT_SIZE;
      branch_type_  = ARM64_B_Branch;
    } else {
      DLOG("%s", "[!] Can't find any cove cave, change to ldr branch");
    }
  }

  if (region)
    delete region;
  else {
    DLOG("%s", "[*] Use ARM64 Ldr Branch.\n");
    branch_type_  = ARM64_LDR_Branch;
    relocate_size = ARM64_FULL_REDIRECT_SIZE;
  }

  // Gen the relocated code
  Code *code;
  code                              = GenRelocateCode(src_pc, &relocate_size);
  entry_->relocated_origin_function = (void *)code->raw_instruction_start();
  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // save original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// Add pre_call(prologue) handler before running the origin function,
void ARM64InterceptRouting::BuildPreCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *cte = ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = cte->address;

  // build the fast forward trampoline jump to the normal routing(prologue_routing_dispatch).
  if (branch_type_ == ARM64_B_Branch)
    BuildFastForwardTrampoline();

  DLOG("[*] create pre call closure trampoline to 'prologue_routing_dispatch' at %p\n", cte->address);
}

// Add post_call(epilogue) handler before `Return` of the origin function, as implementation is replace the origin `Return Address` of the function.
void ARM64InterceptRouting::BuildPostCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)epilogue_routing_dispatch);
  entry_->epilogue_dispatch_bridge = closure_trampoline_entry->address;

  DLOG("[*] create post call closure trampoline to 'prologue_routing_dispatch' at %p\n",
       closure_trampoline_entry->address);
}

// If BranchType is B_Branch and the branch_range of `B` is not enough, build the transfer to forward the b branch, if
void ARM64InterceptRouting::BuildFastForwardTrampoline() {
  TurboAssembler turbo_assembler_;
  CodeGen codegen(&turbo_assembler_);
  if (entry_->type == kFunctionInlineHook) {
    codegen.LiteralLdrBranch((uint64_t)entry_->replace_call);
    DLOG("[*] create fast forward trampoline to 'replace_call' %p\n", entry_->replace_call);
  } else if (entry_->type == kDynamicBinaryInstrumentation) {
    codegen.LiteralLdrBranch((uint64_t)entry_->prologue_dispatch_bridge);
    DLOG("[*] create fast forward trampoline to 'prologue_dispatch_bridge' %p\n", entry_->prologue_dispatch_bridge);
  } else if (entry_->type == kFunctionWrapper) {
    DLOG("[*] create fast forward trampoline to 'prologue_dispatch_bridge' %p\n", entry_->prologue_dispatch_bridge);
    codegen.LiteralLdrBranch((uint64_t)entry_->prologue_dispatch_bridge);
  }

  AssemblerCode *code             = AssemblerCode::FinalizeTurboAssembler(&turbo_assembler_);
  entry_->fast_forward_trampoline = (void *)code->raw_instruction_start();
}

// Add dbi_call handler before running the origin instructions
void ARM64InterceptRouting::BuildDynamicBinaryInstrumentationRouting() {
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
void ARM64InterceptRouting::Commit() {
  Active();
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void ARM64InterceptRouting::Active() {
  uint64_t target_address = (uint64_t)entry_->target_address;
  TurboAssembler turbo_assembler_;
#define _ turbo_assembler_.
  if (branch_type_ == ARM64_B_Branch) {
    _ b((int64_t)entry_->fast_forward_trampoline - (int64_t)target_address);

  } else {
    CodeGen codegen(&turbo_assembler_);
    // check if enable "fast forward trampoline"
    if (entry_->fast_forward_trampoline)
      codegen.LiteralLdrBranch((uint64_t)entry_->fast_forward_trampoline);
    else
      codegen.LiteralLdrBranch((uint64_t)entry_->prologue_dispatch_bridge);
  }

  CodeChunk::MemoryOperationError err;
  err = CodeChunk::PatchCodeBuffer((void *)target_address, turbo_assembler_.GetCodeBuffer());
  CHECK_EQ(err, CodeChunk::kMemoryOperationSuccess);
  Code::FinalizeFromAddress(target_address, turbo_assembler_.CodeSize());

  DLOG("[*] Active the routing at %p\n", entry_->target_address);
}
