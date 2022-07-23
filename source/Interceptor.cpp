#include "Interceptor.h"

Interceptor *Interceptor::instance = nullptr;

Interceptor *Interceptor::SharedInstance() {
  if (Interceptor::instance == nullptr) {
    Interceptor::instance = new Interceptor();
  }
  return Interceptor::instance;
}

HookEntry *Interceptor::findHookEntry(addr_t addr) {
  for (auto *entry : entries) {
    if (entry->patched_addr == addr) {
      return entry;
    }
  }
  return nullptr;
}

void Interceptor::addHookEntry(HookEntry *entry) {
  entries.push_back(entry);
}

void Interceptor::removeHookEntry(addr_t addr) {
  for (auto iter = entries.begin(); iter != entries.end(); iter++) {
    if ((*iter)->patched_addr == addr) {
      entries.erase(iter);
      break;
    }
  }
}

const HookEntry *Interceptor::getEntry(int i) {
  return entries[i];
}

int Interceptor::count() {
  return entries.size();
}
