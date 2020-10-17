#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "dobby_internal.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

std::vector<addr_t> remap_addr_array;

void DumpMemoryRemapPoint() {
  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(Interceptor::entries);
  while ((entry = reinterpret_cast<HookEntry *>(iter->getNextObject())) != NULL) {
    remap_addr_array->push_back(entry->target_address == address);
  }
}