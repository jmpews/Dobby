#include "Interceptor.h"

Interceptor *Interceptor::priv_interceptor_ = nullptr;
InterceptorOptions Interceptor::options_    = {0};

Interceptor *Interceptor::SharedInstance() {
  if (Interceptor::priv_interceptor_ == NULL) {
    Interceptor::priv_interceptor_ = new Interceptor();
  }
  return Interceptor::priv_interceptor_;
}

HookEntry *Interceptor::FindHookEntry(void *address) {
  for (auto entry : entries) {
    if (entry->target_address == address) {
      return entry;
    }
  }
  return NULL;
}

void Interceptor::AddHookEntry(HookEntry *entry) {
  entries.push_back(entry);
}
