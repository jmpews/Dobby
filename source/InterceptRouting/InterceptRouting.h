#ifndef INTERCEPTER_ROUTING_H
#define INTERCEPTER_ROUTING_H

#include "Interceptor.h"

#include "ExecMemory/AssemblyCode.h"

class CodeBuffer;

extern CodeBufferBase *GenerateNormalTrampolineBuffer(void *from, void *to);

extern AssemblyCode *GenRelocateCode(void *buffer, int *relocate_size, addr_t from_pc, addr_t to_pc);

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

  // trampoline
  AssemblyCode *trampoline_;

  // trampoline buffer before active
  CodeBufferBase *trampoline_buffer_;

  // trampoline target
  void *trampoline_target_;
};
#endif
