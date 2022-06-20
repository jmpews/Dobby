#pragma once

#include "dobby_internal.h"
#include "HookEntry.h"

class Interceptor {
private:
  static Interceptor *instance;
  tinystl::vector<HookEntry *> entries;

public:
  static Interceptor *SharedInstance();

public:
  HookEntry *findHookEntry(addr_t addr);

  void removeHookEntry(addr_t addr);

  void addHookEntry(HookEntry *entry);

  int count();
};