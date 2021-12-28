#pragma once


#include "dobby_internal.h"
#include "HookEntry.h"

class Interceptor {
public:

  Interceptor(){

  }

private:
  static Interceptor *shared_interceptor;

public:
  static Interceptor *SharedInstance();

public:
  HookEntry *findHookEntry(addr_t addr);

  void removeHookEntry(addr_t addr);

  void addHookEntry(HookEntry *entry);

  int getHookEntryCount();



private:
  std::vector<HookEntry *> entries;


};