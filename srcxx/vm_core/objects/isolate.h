#ifndef ZZ_OBJECTS_ISOLATE_H_
#define ZZ_OBJECTS_ISOLATE_H_

#include "vm_core/globals.h"
#include "vm_core/platform/platform.h"
#include "vm_core/objects/heap.h"

namespace zz {

class Isolate {
public:
  static Isolate *Current() {
    Isolate *isolate = reinterpret_cast<Isolate *>(OSThread::GetExistingThreadLocal(isolate_key_));
    return isolate;
  }

  static void SetIsolateThreadLocals(Isolate *isolate);

  void *GetExecutableMemory(uword size);

private:
  Heap heap_;

  static OSThread::LocalStorageKey isolate_key_;
};

} // namespace zz

#endif