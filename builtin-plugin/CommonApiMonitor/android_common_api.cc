
#include "dobby.h"

#include "logging/logging.h"

#include <stdio.h>

#include <map>

std::map<void *, const char *> *func_map;

void common_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  auto iter = func_map->find(info->function_address);
  if(iter != func_map->end()) {
    LOG(1, "func %s:%p invoke", iter->first, iter->second);
  }
}

const char *func_array[] = {
//    "_ZN3art2gc4Heap13PreZygoteForkEv",

//    "__loader_dlopen",
    "dlsym",
//    "dlclose"
};

#if 1
__attribute__((constructor)) static void ctor() {
  void *func = NULL;

  func_map = new std::map<void *, const char *>();

  for (int i = 0; i < sizeof(func_array) / sizeof(char *); ++i) {
    func = DobbySymbolResolver(NULL, func_array[i]);
    func_map->insert(std::pair<void *, const char *>(func, func_array[i]));
    DobbyInstrument(func, common_handler);
  }

}
#endif