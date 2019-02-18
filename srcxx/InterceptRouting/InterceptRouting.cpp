#include "hookzz_internal.h"

#include "logging/logging.h"

#include "InterceptRouting.h"
#include "ExecMemory/CodeBuffer/CodeBufferBase.h"

using namespace zz;

void InterceptRouting::Prepare() {
  Interceptor *interceptor             = Interceptor::SharedInstance();
  int relocate_size                    = 0;
  AssemblyCode *relocatedCode          = NULL;
  CodeBufferBase *trampolineCodeBuffer = NULL;

  // get the trampoline size
  trampolineCodeBuffer = (CodeBufferBase *)GenTrampoline((void *)entry_->target_address, NULL);
  relocate_size        = trampolineCodeBuffer->getSize();

  // gen the relocated code
  relocatedCode = GenRelocateCode((void *)entry_->target_address, &relocate_size, (addr_t)entry_->target_address, 0);

  // set the relocated instruction address
  entry_->relocated_origin_function = (void *)relocatedCode->raw_instruction_start();

  DLOG("[*] Relocate origin (prologue) instruction at %p.\n", (void *)code->raw_instruction_start());

  // save original prologue
  _memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
void InterceptRouting::Active() {
  CodeBufferBase *trampolineCodeBuffer = NULL;
  trampolineCodeBuffer                 = (CodeBufferBase *)GenTrampoline(entry_->target_address, GetTrampolineTarget());

  AssemblyCode::FinalizeFromCodeBuffer(entry_->target_address, trampolineCodeBuffer);

  DLOG("[*] Active the routing at %p\n", entry_->target_address);
}

void InterceptRouting::Commit() {
  Active();
}

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
