#ifndef INTERCEPTER_ROUTING_H
#define INTERCEPTER_ROUTING_H

#include "Interceptor.h"

#include "ExecMemory/AssemblyCode.h"

class CodeBuffer;

extern CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to);

extern void GenRelocateCode(void *buffer, AssemblyCode *origin, AssemblyCode *relocated);

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

  // entry =====

  HookEntry *GetHookEntry();

  // relocated

  void GenerateRelocatedCode();

  // trampoline =====

  int PredefinedTrampolineSize();

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
  // hook entry
  HookEntry *entry_;

  // origin code
  AssemblyCode *origin_;

  // origin code
  AssemblyCode *relocated_;

  // trampoline
  AssemblyCode *trampoline_;

  // trampoline buffer before active
  CodeBufferBase *trampoline_buffer_;

  // trampoline target
  void *trampoline_target_;
};
#endif
