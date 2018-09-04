#include "srcxx/InterceptRouting.h"
#include "srcxx/Interceptor.h"
#include "hookzz_internal.h"

#include "Logging.h"

#include "AssemblyClosureTrampoline.h"
#include "intercept_routing_handler.h"

#include "vm_core/modules/assembler/assembler-arm64.h"
#include "vm_core/modules/codegen/codegen-arm64.h"

using namespace zz::arm64;

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_FULL_REDIRECT_SIZE 16
#define ARM64_NEAR_JUMP_RANGE ((1 << 25) << 2)

void InterceptRouting::Prepare() {
  uint64_t src_pc          = (uint64_t)entry_->target_address;
  int need_relocated_size  = ARM64_FULL_REDIRECT_SIZE;
  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->options().enable_b_branch) {
    DLOG("Enable b branch maybe cause crash, if crashed, please disable it.\n");
    need_relocated_size = ARM64_TINY_REDIRECT_SIZE;
  }

  // save original prologue
  memcpy(entry_->origin_instructions.data, entry_->target_address, need_relocated_size);
  entry_->origin_instructions.size    = need_relocated_size;
  entry_->origin_instructions.address = entry_->target_address;
}

void InterceptRouting::BuildPreCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = closure_trampoline_entry->address;

  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->options().enable_b_branch) {
    BuildFastForwardTrampoline();
  }
  DLOG("create pre call closure trampoline to %p\n", closure_trampoline_entry->address);
}

void InterceptRouting::BuildFastForwardTrampoline() {
  TurboAssembler *turbo_assembler_;
#define _ turbo_assembler_
  CodeGen codegen(turbo_assembler_);
  if (entry_->type == kFunctionInlineHook) {
    codegen.LiteralBrBranch((uint64_t)entry_->replace_call);
  } else if (entry_->type == kDynamicBinaryInstrumentation) {
    codegen.LiteralBrBranch((uint64_t)entry_->prologue_dispatch_bridge);
  } else if (entry_->type == kFunctionWrapper) {
    codegen.LiteralBrBranch((uint64_t)entry_->prologue_dispatch_bridge);
  }
}

void InterceptRouting::BuildDynamicBinaryInstrumentationRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)prologue_routing_dispatch);
  entry_->prologue_dispatch_bridge = closure_trampoline_entry->address;

  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->options().enable_b_branch) {
    BuildFastForwardTrampoline();
  }
  DLOG("create dynamic binary instrumentation call closure trampoline to %p\n", closure_trampoline_entry->address);
}

void InterceptRouting::BuildPostCallRouting() {
  // create closure trampoline jump to prologue_routing_dispath with the `entry_` data
  ClosureTrampolineEntry *closure_trampoline_entry =
      ClosureTrampoline::CreateClosureTrampoline(entry_, (void *)epilogue_routing_dispatch);
  entry_->epilogue_dispatch_bridge = closure_trampoline_entry->address;

  DLOG("create post call closure trampoline to %p\n", closure_trampoline_entry->address);
}