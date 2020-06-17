#include "dobby_internal.h"

#include "InterceptRouting.h"
#include "ExecMemory/CodeBuffer/CodeBufferBase.h"
#include "ExtraInternalPlugin/RegisterPlugin.h"
#include "PlatformInterface/ExecMemory/CodePatchTool.h"

using namespace zz;

void InterceptRouting::Prepare() {
  Interceptor *interceptor = Interceptor::SharedInstance();
  int relocate_size        = 0;

  AssemblyCode *relocatedCode    = NULL;
  CodeBufferBase *trampolineCode = NULL;

  // get the trampolineCode size
  trampolineCode = (CodeBufferBase *)GenTrampoline((void *)entry_->target_address, NULL);
  relocate_size  = trampolineCode->getSize();

#define DUMMY_0 0
  // gen the relocated code
  relocatedCode = GenRelocateCode((void *)entry_->target_address, &relocate_size, DUMMY_0, DUMMY_0);

  // set the relocated instruction address
  entry_->relocated_origin_function = (void *)relocatedCode->raw_instruction_start();

  DLOG("Relocate origin (prologue) instruction at %p.\n", (void *)relocatedCode->raw_instruction_start());

#ifndef PLUGIN_DOBBY_DRILL
  // save original prologue
  _memcpy(entry_->origin_instructions.data, entry_->target_address, relocate_size);
  entry_->origin_instructions.size    = relocate_size;
  entry_->origin_instructions.address = entry_->target_address;
#endif
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
// Patch the address with branch instr
// X86_64(14 bytes): [jmp rip] [data_address]
// ARM64(16 bytes): [ldr x17, 4] [br x17] [data_address]
// ARM(8 bytes): [ldr pc, 4] [data_address]
void InterceptRouting::Active() {
  CodePatch(entry_->target_address, trampoline_->getRawBuffer(), trampoline_->getSize());

  DLOG("Active the routing at %p\n", entry_->target_address);
}

void InterceptRouting::Commit() {
  bool handle_by_plugin = false;

  if (ExtraInternalPlugin::plugins_) {
    RoutingPlugin *plugin        = NULL;
    LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(ExtraInternalPlugin::plugins_);
    while ((plugin = reinterpret_cast<RoutingPlugin *>(iter->getNextObject())) != NULL) {
      if (plugin->Active(this))
        handle_by_plugin = true;
    }
    delete iter;
  }

  if (!handle_by_plugin)
    this->Active();
}

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
