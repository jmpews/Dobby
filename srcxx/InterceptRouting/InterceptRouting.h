#ifndef HOOKZZ_INTERCEPTROUTING_H_
#define HOOKZZ_INTERCEPTROUTING_H_

#include "Interceptor.h"

#include "ExecMemory/AssemblyCode.h"

class CodeBuffer;

extern CodeBuffer *GenTrampoline(void *from, void *to);

extern zz::AssemblyCode *GenRelocateCode(void *buffer, int *relocate_size, addr_t from_pc, addr_t to_pc);

class InterceptRouting {
public:
  InterceptRouting(HookEntry *entry) : entry_(entry) {
    entry->route = this;
  }

  virtual void Dispatch() = 0;

  virtual void Prepare();

  virtual void Active();

  void Commit();

  HookEntry *GetHookEntry();

  virtual void *GetTrampolineTarget() = 0;

private:
protected:
  HookEntry *entry_;
};
#endif
