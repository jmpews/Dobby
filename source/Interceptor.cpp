#include "Interceptor.h"

#include "dobby_internal.h"

Interceptor *      Interceptor::priv_interceptor_ = nullptr;
InterceptorOptions Interceptor::options_          = {0};

Interceptor *Interceptor::SharedInstance() {
  if (Interceptor::priv_interceptor_ == NULL) {
    Interceptor::priv_interceptor_          = new Interceptor();
    Interceptor::priv_interceptor_->entries = new LiteMutableArray(8);
  }
  return Interceptor::priv_interceptor_;
}

HookEntry *Interceptor::FindHookEntry(void *address) {
  HookEntry *entry = NULL;

  LiteCollectionIterator iter(entries);
  while ((entry = reinterpret_cast<HookEntry *>(iter.getNextObject())) != NULL) {
    if (entry->target_address == address) {
      return entry;
    }
  }
  return NULL;
}

void Interceptor::AddHookEntry(HookEntry *entry) {
  entries->pushObject((LiteObject *)entry);
}
