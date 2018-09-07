#include "vm_core/objects/isolate.h"

void Isolate::SetIsolateThreadLocals(Isolate *isolate) {
  Thread::SetThreadLocal(isolate_key_, isolate);
}
