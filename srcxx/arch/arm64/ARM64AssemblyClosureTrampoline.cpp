#include "srcxx/AssemblyClosureTrampoline.h"

#include "vm_core/base/objects/code.h"

#include "vm_core/arch/arm64/registers-arm64.h"
#include "vm_core/modules/assembler/assembler-arm64.h"

extern void closure_trampoline_template();

using namespace zz::arm64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline() {

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
  // use closure trampoline template code, find the executable memory and patch it.

#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)
  zz::Code *code = zz::Code::FinalizeCode(closure_trampoline_template, CLOSURE_TRAMPOLINE_SIZE);

#else
  // use assembler and codegen modules instead of template_code

  Assembler *assembler_;
  TurboAssembler *turbo_assembler__;

#define _ assembler_->
#define __ turbo_assembler__->

  Label *ClourseTrampolineEntryPtr;
  _ ldr(Register::X(17), ClourseTrampolineEntryPtr);
  _ ldr(Register::X(16), OFFSETOF(ClourseTrampolineEntry, carray_data));
  _ ldr(Register::X(17), OFFSETOF(ClourseTrampolineEntry, forward_code));
  _ br(Register::X17);

  uintptr_t dummy_addr = 0;
  assembler_->EmitData(&dummy_addr, sizeof(void *));

#endif
}