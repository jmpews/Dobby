//
// Created by z on 2018/6/14.
//

#include "Interceptor.h"

Interceptor *Interceptor::GETInstance() {
  if (priv_interceptor == NULL) {
    priv_interceptor     = new Interceptor();
    priv_interceptor->mm = MemoryManager::GetInstance();
  }
  return priv_interceptor;
}

HookEntry *Interceptor::findHookEntry(void *target_address) {
  for (auto entry : hook_entries) {
    if (entry->target_address == target_address) {
      return entry;
    }
  }
  return NULL;
}

void Interceptor::addHookEntry(HookEntry *entry) {
  hook_entries.push_back(entry);
}
