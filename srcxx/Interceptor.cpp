#include "srcxx/Interceptor.h"

Interceptor *Interceptor::SharedInstance() {
  if (priv_interceptor_ == NULL) {
    priv_interceptor_     = new Interceptor();
  }
  return priv_interceptor_;
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
