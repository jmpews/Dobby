#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "core/modules/assembler/assembler-arm64.h"

extern void closure_trampoline_template();

using namespace zz;
using namespace zz::arm64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {
  ClosureTrampolineEntry *entry = new ClosureTrampolineEntry;
// use assembler and codegen modules instead of template_code
// _ ldr(Register::X(16), OFFSETOF(ClosureTrampolineEntry, carry_data));
// _ ldr(Register::X(17), OFFSETOF(ClosureTrampolineEntry, carry_handler));
#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#define _ turbo_assembler_.
  TurboAssembler turbo_assembler_(0);

  PseudoLabel entry_label;
  PseudoLabel forward_bridge_label;

  _ Ldr(x16, &entry_label);
  _ Ldr(x17, &forward_bridge_label);
  _ br(x17);
  _ PseudoBind(&entry_label);
  _ EmitInt64((uint64_t)entry);
  _ PseudoBind(&forward_bridge_label);
  _ EmitInt64((uint64_t)get_closure_bridge());

  AssemblyCode *code = AssemblyCode::FinalizeFromTurboAssember(reinterpret_cast<AssemblerBase *>(&turbo_assembler_));

  entry->address       = (void *)code->raw_instruction_start();
  entry->carry_data    = carry_data;
  entry->carry_handler = carry_handler;
  entry->size          = code->raw_instruction_size();
  return entry;
}

#endif