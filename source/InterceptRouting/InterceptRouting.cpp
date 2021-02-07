#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

using namespace zz;

void InterceptRouting::Prepare() {
}

// Generate relocated code
void InterceptRouting::GenerateRelocatedCode() {
  // generate original code
  AssemblyCodeChunk *origin         = NULL;
  int                trampoline_len = trampoline_buffer_->getSize();
  origin  = AssemblyCodeBuilder::FinalizeFromAddress((addr_t)entry_->target_address, trampoline_len);
  origin_ = origin;

  // generate the relocated code
  AssemblyCodeChunk *relocated = NULL;
  relocated                    = AssemblyCodeBuilder::FinalizeFromAddress(0, 0);
  relocated_                   = relocated;

  void *relocate_buffer = NULL;
  relocate_buffer       = entry_->target_address;

  GenRelocateCodeAndBranch(relocate_buffer, origin, relocated);
  if (relocated->raw_instruction_start() == 0)
    return;

  // set the relocated instruction address
  entry_->relocated_origin_instructions = (void *)relocated->raw_instruction_start();
  DLOG(1, "[insn relocate] origin %p - %d", origin->raw_instruction_start(), origin->raw_instruction_size());
  DLOG(1, "[insn relocate] relocated %p - %d", relocated->raw_instruction_start(), relocated->raw_instruction_size());

  // save original prologue
  memcpy((void *)entry_->origin_chunk_.chunk_buffer, (void *)origin_->raw_instruction_start(),
         origin_->raw_instruction_size());
  entry_->origin_chunk_.chunk.re_init_region_range(origin_);
}

/*
X86_64 (14 bytes)
  [jmp rip]
  [branch_address]

ARM64 - 16 bytes
  [ldr literal]
  [br]
  [branch_address]

ARM64 - 12 bytes
  [adrp]
  [add]
  [br]

ARM - 8 bytes:
  [ldr pc literal]
  [data_address]
*/

// Active routing, will patch the origin insturctions, and forward to our custom routing.
// Patch the address with branch instr
void InterceptRouting::Active() {
  void *patch_address = NULL;
  patch_address       = (void *)origin_->raw_instruction_start();

  CodePatch(patch_address, (uint8_t *)trampoline_buffer_->getRawBuffer(), trampoline_buffer_->getSize());
  DLOG(1, "[intercept routing] Active patch %p", patch_address);
}

void InterceptRouting::Commit() {
  this->Active();
}

#if 0
int InterceptRouting::PredefinedTrampolineSize() {
#if __arm64__
  return 12;
#elif __arm__
  return 8;
#endif
}
#endif

void InterceptRouting::GenerateTrampolineBuffer(void *src, void *dst) {
  CodeBufferBase *trampoline_buffer = NULL;
  // if near branch trampoline plugin enabled
  if (ExtraInternalPlugin::near_branch_trampoline) {
    RoutingPlugin *plugin = NULL;
    plugin                = reinterpret_cast<RoutingPlugin *>(ExtraInternalPlugin::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DLOG(0, "Failed enable near branch trampoline plugin");
    }
  }

  if (this->GetTrampolineBuffer() == NULL) {
    trampoline_buffer = GenerateNormalTrampolineBuffer((addr_t)src, (addr_t)dst);
    this->SetTrampolineBuffer(trampoline_buffer);

    DLOG(1, "[trampoline] Generate trampoline buffer %p -> %p", src, dst);
  }
}

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
