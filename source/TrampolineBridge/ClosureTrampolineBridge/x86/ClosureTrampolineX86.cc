#include "platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "dobby_internal.h"

#include "core/assembler/assembler-ia32.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

using namespace zz;
using namespace zz::x86;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {
  ClosureTrampolineEntry *entry = nullptr;
  entry = new ClosureTrampolineEntry;

  AssemblyCode *code = Code(32);
  if (chunk == nullptr) {
    return NULL;
  }

#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->
  TurboAssembler turbo_assembler_(chunk->address);

  int32_t offset = (int32_t)get_closure_bridge() - ((int32_t)chunk->address + 18);

  _ sub(esp, Immediate(4, 32));
  _ mov(Address(esp, 4 * 0), Immediate((int32_t)entry, 32));
  _ jmp(Immediate(offset, 32));

  entry->address = (void *)chunk->raw_instruction_start();
  entry->size = chunk->raw_instruction_size();
  entry->carry_data = carry_data;
  entry->carry_handler = carry_handler;

  CodeBufferBase *buffer = reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer());
  CodePatch(chunk->address, (uint8_t *)buffer->GetBuffer(), buffer->GetBufferSize());

  return entry;
}

#endif