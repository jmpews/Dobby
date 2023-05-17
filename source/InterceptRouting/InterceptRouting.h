#pragma once

#include "Interceptor.h"
#include "MemoryAllocator/AssemblerCodeBuilder.h"
#include "InstructionRelocation/InstructionRelocation.h"
#include "TrampolineBridge/Trampoline/Trampoline.h"
#include "RoutingPlugin.h"
#include "NearBranchTrampoline/NearBranchTrampoline.h"

Trampoline *GenerateNearTrampolineBuffer(addr_t src, addr_t dst);
Trampoline *GenerateNormalTrampolineBuffer(addr_t from, addr_t to);

struct InterceptRouting {
  Interceptor::Entry *entry = 0;
  Trampoline *trampoline = 0;
  Trampoline *near_trampoline = 0;
  int error = 0;

  explicit InterceptRouting(Interceptor::Entry *entry) : entry(entry) {
  }

  ~InterceptRouting() {
    if (trampoline) {
      // TODO: free code block
      delete trampoline;
    }
    if (near_trampoline) {
      // TODO: free code block
      delete near_trampoline;
    }
  }

  virtual void Prepare() {
  }
  virtual void DispatchRouting() {
  }
  void Commit() {
  }

  virtual addr_t TrampolineTarget() {
    UNREACHABLE();
    return -1;
  }

  addr_t trampoline_addr() {
    if (near_trampoline)
      return near_trampoline->addr();
    return trampoline->addr();
  }

  size_t trampoline_size() {
    if (near_trampoline)
      return near_trampoline->size();
    return trampoline->size();
  }

  virtual void Active() {
    __FUNC_CALL_TRACE__();
    auto ret = DobbyCodePatch((void *)entry->addr, (uint8_t *)trampoline_addr(), trampoline_size());
    error |= (ret != 0);
  }

  bool GenerateTrampoline() {
    __FUNC_CALL_TRACE__();
    addr_t from = entry->addr;
    features::arm_thumb_fix_addr(from);

    addr_t to = TrampolineTarget();

    if (0 && RoutingPluginManager::near_branch_trampoline) {
      auto plugin = static_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
      plugin->GenerateTrampolineBuffer(this, from, to);
    }

    if (g_enable_near_trampoline) {
      near_trampoline = GenerateNearTrampolineBuffer(from, to);
    }

    if (!near_trampoline) {
      trampoline = GenerateNormalTrampolineBuffer(from, to);
    }
    return true;
  }

  void GenerateRelocatedCode() {
    __FUNC_CALL_TRACE__();
    if (trampoline_addr() == 0) {
      ERROR_LOG("GenerateTrampoline must be called first");
      error = 1;
    }

    auto code_addr = entry->addr;
    features::arm_thumb_fix_addr(code_addr);
    auto preferred_size = trampoline_size();
    auto origin = CodeMemBlock(code_addr, preferred_size);
    auto relocated = CodeMemBlock(0, 0);
    GenRelocateCodeAndBranch((void *)code_addr, &origin, &relocated);
    if (relocated.size == 0) {
      error = 1;
      return;
    }
    DEBUG_LOG("origin: %p, size: %d", origin.addr(), origin.size);
    debug_hex_log_buffer((uint8_t *)origin.addr(), origin.size);
    DEBUG_LOG("relocated: %p, size: %d", relocated.addr(), relocated.size);
    debug_hex_log_buffer((uint8_t *)relocated.addr(), relocated.size);

    entry->patched = origin;
    entry->relocated = relocated;
  }

  void BackupOriginCode() {
    __FUNC_CALL_TRACE__();
    entry->backup_orig_code();
  }
};
