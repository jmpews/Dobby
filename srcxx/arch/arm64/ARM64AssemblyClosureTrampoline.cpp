#include "srcxx/AssemblyClosureTrampoline.h"

#include "vm_core/base/objects/code.h"

#include "vm_core/arch/arm64/registers-arm64.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

extern void closure_trampoline_template();

using namespace zz::arm64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline() {

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)
  // use closure trampoline template code, find the executable memory and patch it.
  zz::Code *code = zz::Code::FinalizeCode(closure_trampoline_template, CLOSURE_TRAMPOLINE_SIZE);

#else
// use assembler and codegen modules instead of template_code
#define _ assembler_->
#define __ turbo_assembler__->
  Assembler *assembler_;
  TurboAssembler *turbo_assembler__;

  Label ClosureTrampolineEntryPtr;
  _ ldr(Register::X(17), &ClosureTrampolineEntryPtr);
  _ ldr(Register::X(16), OFFSETOF(ClosureTrampolineEntry, carray_data));
  _ ldr(Register::X(17), OFFSETOF(ClosureTrampolineEntry, forward_code));
  _ br(Register::X(17));
  Bind(&ClosureTrampolineEntryPtr);
  EmitInt64(0); // dummy address

#endif
}