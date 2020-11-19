#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "dobby_internal.h"

#include "core/modules/assembler/assembler-ia32.h"

#include "ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.h"

extern void closure_trampoline_template();

using namespace zz;
using namespace zz::x86;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {

  ClosureTrampolineEntry *entry = new ClosureTrampolineEntry;

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#define _  turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->

  AssemblyCodeChunk *cchunk = MemoryArena::AllocateCodeChunk(32);
  if (cchunk == nullptr) {
    return NULL;
  }
  // init assembler
  TurboAssembler turbo_assembler_(cchunk->address);

  int32_t offset = (int32_t)cchunk->address + 8 - (int32_t)carry_handler;

  _ sub(esp, Immediate(4, 32));
  _ mov(Address(esp, 4 * 0), Immediate((int32_t)entry, 32));
  _ jmp(Immediate(offset, 32));

  entry->address       = (void *)cchunk->raw_instruction_start();
  entry->carry_data    = carry_data;
  entry->carry_handler = carry_handler;
  entry->size          = cchunk->raw_instruction_size();

  return entry;
}

#endif