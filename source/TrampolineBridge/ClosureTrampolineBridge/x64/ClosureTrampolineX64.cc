#include "platform_macro.h"
#if defined(TARGET_ARCH_X64)

#include "dobby_internal.h"

#include "core/assembler/assembler-x64.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

using namespace zz;
using namespace zz::x64;

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline(void *carry_data, void *carry_handler) {
  ClosureTrampolineEntry *entry = nullptr;
  entry = new ClosureTrampolineEntry;

  AssemblyCodeChunk *chunk = MemoryArena::AllocateCodeChunk(32);
  if (chunk == nullptr) {
    return NULL;
  }
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->
  TurboAssembler turbo_assembler_(0);

  uint8_t *push_rip_6 = (uint8_t *)"\xff\x35\x06\x00\x00\x00";
  uint8_t *jmp_rip_8 = (uint8_t *)"\xff\x25\x08\x00\x00\x00";

  __ EmitBuffer(push_rip_6, 6);
  __ EmitBuffer(jmp_rip_8, 6);
  __ Emit64((uint64_t)entry);
  __ Emit64((uint64_t)get_closure_bridge());

  entry->address = chunk->address;
  entry->size = chunk->length;
  entry->carry_data = carry_data;
  entry->carry_handler = carry_handler;

  CodeBufferBase *buffer = reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer());
  CodePatch(chunk->address, (uint8_t *)buffer->GetBuffer(), buffer->GetBufferSize());

  return entry;
}

#endif