#include "vm_core/objects/isolate.h"

namespace zz {

Thread::LocalStorageKey Isolate::isolate_key_;

void Isolate::SetIsolateThreadLocals(Isolate *isolate) {
  Thread::SetThreadLocal(isolate_key_, isolate);
}

} // namespace zz