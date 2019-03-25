#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "ExecMemory/AssemblyCode.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/modules/assembler/assembler-arm64.h"

extern void closure_trampoline_template();

using namespace zz;
using namespace zz::arm64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {

  ClosureTrampolineEntry *entry = new ClosureTrampolineEntry;

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)
  // use closure trampoline template code, find the executable memory and patch it.
  Code *code = Code::FinalizeCodeFromAddress(closure_trampoline_template, CLOSURE_TRAMPOLINE_SIZE);

#else
// use assembler and codegen modules instead of template_code
// _ ldr(Register::X(16), OFFSETOF(ClosureTrampolineEntry, carry_data));
// _ ldr(Register::X(17), OFFSETOF(ClosureTrampolineEntry, carry_handler));
#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#define _ turbo_assembler_.
  TurboAssembler turbo_assembler_;

  PseudoLabel ClosureTrampolineEntry;
  PseudoLabel ForwardCode_ClosureBridge;

  // ===
  _ Ldr(x16, &ClosureTrampolineEntry);
  _ Ldr(x17, &ForwardCode_ClosureBridge);
  _ br(x17);
  _ PseudoBind(&ClosureTrampolineEntry);
  _ EmitInt64((uint64_t)entry);
  _ PseudoBind(&ForwardCode_ClosureBridge);
  _ EmitInt64((uint64_t)get_closure_bridge());
  // ===

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(reinterpret_cast<AssemblerBase *>(&turbo_assembler_));

  entry->address       = (void *)code->raw_instruction_start();
  entry->carry_data    = carry_data;
  entry->carry_handler = carry_handler;
  entry->size          = code->raw_instruction_size();
  return entry;
#endif
}
