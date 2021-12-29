#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

using namespace zz;

void InterceptRouting::Prepare() {
}

// generate relocated code
bool InterceptRouting::GenerateRelocatedCode() {
  uint32_t trampoline_size = GetTrampolineBuffer()->GetBufferSize();

  // generate original code
  origin_ = new CodeMemBlock(entry_->patched_insn_addr, trampoline_size);

  // generate the relocated code
  relocated_ = new CodeMemBlock();

  auto buffer = (void *)entry_->patched_insn_addr;
  GenRelocateCodeAndBranch(buffer, origin_, relocated_);
  if (relocated_->size == 0)
    return false;

  // set the relocated instruction address
  entry_->relocated_insn_addr = relocated_->addr;
  DLOG(0, "[insn relocate] origin %p - %d", origin_->addr, origin_->size);
  hexdump((uint8_t *)origin_->addr, origin_->size);

  DLOG(0, "[insn relocate] relocated %p - %d", relocated_->addr, relocated_->size);
  hexdump((uint8_t *)relocated_->addr, relocated_->size);

  // save original prologue
  memcpy((void *)entry_->origin_insns, (void *)origin_->addr, origin_->size);
  return true;
}

bool InterceptRouting::GenerateTrampolineBuffer(addr_t src, addr_t dst) {
  CodeBufferBase *tramp_buffer = nullptr;

  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    RoutingPluginInterface *plugin = nullptr;
    plugin = static_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DLOG(0, "Failed enable near branch trampoline plugin");
    }
  }

  if (GetTrampolineBuffer() == nullptr) {
    tramp_buffer = GenerateNormalTrampolineBuffer(src, dst);
    SetTrampolineBuffer(tramp_buffer);
  }
  return true;
}

// Active routing, patch origin insturctions as trampoline
void InterceptRouting::Active() {
  MemoryOperationError err;
  err = CodePatch((void *)entry_->patched_insn_addr, trampoline_buffer_->GetBuffer(), trampoline_buffer_->GetBufferSize());
  if (err == kMemoryOperationSuccess) {
    DLOG(0, "[intercept routing] active");
  } else
    
  ERROR_LOG("[intercept routing] active failed");
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
