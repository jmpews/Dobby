#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

using namespace zz;

void InterceptRouting::Prepare() {
}

// Generate relocated code
bool InterceptRouting::GenerateRelocatedCode(uint32_t trampoline_size) {
  CHECK_EQ(GetTrampolineBuffer()->GetBufferSize(), trampoline_size);

  // generate original code
  origin_ = new AssemblyCode {.begin = entry_->target_address, .size = trampoline_size};

  // generate the relocated code
  relocated_ = new AssemblyCode();

  void *relocate_buffer = nullptr;
  relocate_buffer = entry_->target_address;

  GenRelocateCodeAndBranch(relocate_buffer, origin_, relocated_);
  if (relocated_->size == 0)
    return false;

  // set the relocated instruction address
  entry_->relocated_origin_instructions = relocated_->begin;
  DLOG(0, "[insn relocate] origin %p - %d", origin_->begin, origin_->size);
  hexdump((uint8_t *)origin_->begin, origin_->size);

  DLOG(0, "[insn relocate] relocated %p - %d", relocated_->begin, relocated_->size);
  hexdump((uint8_t *)relocated_->begin, relocated_->size);

  // save original prologue
  memcpy((void *)entry_->origin_code_.origin_code_buffer, origin_->begin, origin_->size);
  return true;
}

bool InterceptRouting::GenerateTrampolineBuffer(void *src, void *dst) {
  CodeBufferBase *trampoline_buffer = nullptr;
  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    RoutingPluginInterface *plugin = nullptr;
    plugin = reinterpret_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DLOG(0, "Failed enable near branch trampoline plugin");
    }
  }

  if (this->GetTrampolineBuffer() == nullptr) {
    trampoline_buffer = GenerateNormalTrampolineBuffer((addr_t)src, (addr_t)dst);
    this->SetTrampolineBuffer(trampoline_buffer);
  }
  return true;
}

// Active routing, will patch the origin insturctions, and forward to our custom routing.
// Patch the address with branch instr
void InterceptRouting::Active() {
  void *patch_addr = nullptr;
  patch_addr = origin_->begin;
  MemoryOperationError err;
  err = CodePatch(patch_addr, (uint8_t *)trampoline_buffer_->GetBuffer(), trampoline_buffer_->GetBufferSize());
  if (err == kMemoryOperationSuccess) {
    DLOG(0, "[intercept routing] active");
  }
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

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
