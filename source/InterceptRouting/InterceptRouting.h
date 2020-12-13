#ifndef INTERCEPT_ROUTING_H
#define INTERCEPT_ROUTING_H

#include "Interceptor.h"
#include "MemoryAllocator/AssemblyCodeBuilder.h"

extern CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to);

extern void GenRelocateCodeAndBranch(void *buffer, AssemblyCodeChunk *origin, AssemblyCodeChunk *relocated);

class InterceptRouting {
public:
  InterceptRouting(HookEntry *entry) : entry_(entry) {
    entry->route = this;

    trampoline_        = NULL;
    trampoline_buffer_ = NULL;
    trampoline_target_ = NULL;
  }

  virtual void Dispatch() = 0;

  virtual void Prepare();

  virtual void Active();

  void Commit();

  HookEntry *GetHookEntry();

  void GenerateRelocatedCode();

  void GenerateTrampolineBuffer(void *src, void *dst);

  void SetTrampolineBuffer(CodeBufferBase *buffer) {
    trampoline_buffer_ = buffer;
  }

  CodeBufferBase *GetTrampolineBuffer() {
    return trampoline_buffer_;
  }

  void SetTrampolineTarget(void *address) {
    trampoline_target_ = address;
  }

  void *GetTrampolineTarget() {
    return trampoline_target_;
  }

protected:
  HookEntry *entry_;

  AssemblyCodeChunk *origin_;

  AssemblyCodeChunk *relocated_;

  AssemblyCodeChunk *trampoline_;

  // trampoline buffer before active
  CodeBufferBase *trampoline_buffer_;

  void *trampoline_target_;
};
#endif
