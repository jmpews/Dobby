#include "srcxx/AssemblyClosureTrampoline.h"

#include "vm_core/objects/code.h"
#include "vm_core/arch/arm64/registers-arm64.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

extern void closure_trampoline_template();

using namespace zz;
using namespace zz::arm64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *forward_code) {

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)
  // use closure trampoline template code, find the executable memory and patch it.
  Code *code = Code::FinalizeCodeFromAddress(closure_trampoline_template, CLOSURE_TRAMPOLINE_SIZE);

#else
// use assembler and codegen modules instead of template_code
#include "srcxx/AssemblyClosureTrampoline.h"
#define _ turbo_assembler_->
  TurboAssembler *turbo_assembler_;

  PseudoLabel ClosureTrampolineEntryPtr;
  _ Ldr(Register::X(17), &ClosureTrampolineEntryPtr);
  _ ldr(Register::X(16), OFFSETOF(ClosureTrampolineEntry, carry_data));
  _ ldr(Register::X(17), OFFSETOF(ClosureTrampolineEntry, forward_code));
  _ br(Register::X(17));
  _ PseudoBind(&ClosureTrampolineEntryPtr);
  _ EmitInt64(0); // dummy address

  turbo_assembler_->Commit();
  Code *code = turbo_assembler_->GetCode();

  return NULL;
#endif
}