#include "Interceptor.h"

Interceptor *Interceptor::shared_interceptor = nullptr;

Interceptor *Interceptor::SharedInstance() {
  if (Interceptor::shared_interceptor == nullptr) {
    Interceptor::shared_interceptor = new Interceptor();
  }
  return Interceptor::shared_interceptor;
}

HookEntry *Interceptor::findHookEntry(addr_t addr) {
  for (int i = 0; i < entries.size(); i++) {
    if (entries[i]->patched_insn_addr == addr) {
      return entries[i];
    }
  }
  return nullptr;
}

void Interceptor::addHookEntry(HookEntry *entry) {
  entries.push_back(entry);
}

void Interceptor::removeHookEntry(addr_t addr) {
  for (auto iter = entries.begin(); iter != entries.end(); iter++) {
    entries.erase(iter);
  }
}

int Interceptor::getHookEntryCount() {
  return entries.size();
}
