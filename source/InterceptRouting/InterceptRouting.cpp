#include "dobby_internal.h"

#include "InterceptRouting.h"
#include "ExecMemory/CodeBuffer/CodeBufferBase.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"
#include "PlatformInterface/ExecMemory/CodePatchTool.h"

using namespace zz;

void InterceptRouting::Prepare() {
  AssemblyCode *relocatedCode = NULL;

  int predefined_relocate_size = 0;
  {
    predefined_relocate_size = this->PredefinedTrampolineSize();
    // if near branch trampoline plugin enabled
    if (ExtraInternalPlugin::near_branch_trampoline) {
      RoutingPlugin *plugin = NULL;
      plugin                = reinterpret_cast<RoutingPlugin *>(ExtraInternalPlugin::near_branch_trampoline);
      predefined_relocate_size         = plugin->PredefinedTrampolineSize();
    }
  }

#define DUMMY_0 0
  // gen the relocated code
  relocatedCode = GenRelocateCode(entry_->target_address, predefined_relocate_size, (addr_t)entry_->target_address, DUMMY_0);

  // set the relocated instruction address
  entry_->relocated_origin_function = (void *)relocatedCode->raw_instruction_start();
  DLOG("[%p] relocate %d bytes, to %p", entry_->target_address, relocatedCode->raw_instruction_size(), entry_->relocated_origin_function);

#ifndef PLUGIN_DOBBY_DRILL
  // save original prologue
  _memcpy(entry_->origin_instructions.data, entry_->target_address, relocatedCode->raw_instruction_size());
  entry_->origin_instructions.size    = relocatedCode->raw_instruction_size();
  entry_->origin_instructions.address = entry_->target_address;
#endif
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
// Patch the address with branch instr
// X86_64(14 bytes): [jmp rip] [data_address]
// ARM64(16 bytes): [ldr x17, 4] [br x17] [data_address]
// ARM64(12 bytes): [ldr x17, 4] [br x17] [data_address]
// ARM(8 bytes): [ldr pc, 4] [data_address]
void InterceptRouting::Active() {
  void *patch_address = 0;
  patch_address = entry_->target_address;
#if __arm__
  patch_address = (void *)((addr_t)patch_address - 1);
#endif
  CodePatch(patch_address, trampoline_buffer_->getRawBuffer(), trampoline_buffer_->getSize());
  LOG("Code patch %p => %p", trampoline_buffer_->getRawBuffer(), entry_->target_address);
}

void InterceptRouting::Commit() {
#if 0
  bool handle_by_plugin = false;
  if (ExtraInternalPlugin::plugins_) {
    RoutingPlugin *plugin        = NULL;
    LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(ExtraInternalPlugin::plugins_);
    while ((plugin = reinterpret_cast<RoutingPlugin *>(iter->getNextObject())) != NULL) {
      DLOG("Run plugin %s", "Unknown");
      if (plugin->Active(this))
        handle_by_plugin = true;
    }
    delete iter;
  }
#endif

  this->Active();
  DLOG("InterceptRouting: >>>>> end <<<<<");
}

int InterceptRouting::PredefinedTrampolineSize() {
#if __arm64__
  return 12;
#elif __arm__
  return 8;
#endif
}

void InterceptRouting::GenerateTrampolineBuffer(void *src, void *dst) {
  CodeBufferBase *trampoline_buffer;
  // if near branch trampoline plugin enabled
  if (ExtraInternalPlugin::near_branch_trampoline) {
    RoutingPlugin *plugin = NULL;
    plugin                = reinterpret_cast<RoutingPlugin *>(ExtraInternalPlugin::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DLOG("Failed enable near branch trampoline plugin");
    }
  }

  if (this->GetTrampolineBuffer() == NULL) {
    trampoline_buffer = GenerateNormalTrampolineBuffer(src, dst);
    this->SetTrampolineBuffer(trampoline_buffer);
  }
}

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
