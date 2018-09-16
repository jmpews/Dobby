#include "srcxx/AssemblyClosureTrampoline.h"

#include "vm_core/arch/arm/registers-arm.h"
#include "vm_core/modules/assembler/assembler-arm.h"
#include "vm_core_extra/code-page-chunk.h"
#include "vm_core_extra/custom-code.h"

#include "AssemblyBridge.h"

extern void closure_trampoline_template();

using namespace zz;
using namespace zz::arm;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {

  ClosureTrampolineEntry *entry = new ClosureTrampolineEntry;

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)
  // use closure trampoline template code, find the executable memory and patch it.
  Code *code = Code::FinalizeCodeFromAddress(closure_trampoline_template, CLOSURE_TRAMPOLINE_SIZE);

#else

// use assembler and codegen modules instead of template_code
#include "srcxx/AssemblyClosureTrampoline.h"
#define _ turbo_assembler_.
  TurboAssembler turbo_assembler_;

  // =====
  _ ldr(r12, MemOperand(pc, 0));
  _ ldr(pc, MemOperand(pc, 0));
  _ Emit((uintptr_t)entry);
  _ Emit((uintptr_t)get_closure_bridge());
  // =====

  AssemblerCode *code = AssemblerCode::FinalizeTurboAssembler(reinterpret_cast<AssemblerBase *>(&turbo_assembler_));

  entry->address       = (void *)code->raw_instruction_start();
  entry->carry_data    = carry_data;
  entry->carry_handler = carry_handler;
  entry->size          = code->raw_instruction_size();
  return entry;
#endif
}
