#include "./android_restriction.h"

#include <elf.h>
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>

#include <fcntl.h> // open

#include <unordered_map>
#include <vector>

#include "dobby_symbol_resolver.h"

#include "common/headers/common_header.h"

// impl at "dobby_symbol_resolver.cc"
extern void *resolve_elf_internal_symbol(const char *library_name, const char *symbol_name);

void *trick_dlopen(const char *filename, int flag) {
  typedef void *(*__loader_dlopen_t)(const char *filename, int flags, const void *caller_addr);
  static __loader_dlopen_t __loader_dlopen = NULL;
  if (!__loader_dlopen)
    __loader_dlopen = (__loader_dlopen_t)DobbySymbolResolver(NULL, "__loader_dlopen");

  // fake caller address
  return __loader_dlopen(filename, flag, (void *)__loader_dlopen);
}

std::vector<soinfo_t> linker_solist;
std::vector<soinfo_t> linker_get_solist() {
  if (!linker_solist.empty()) {
    linker_solist.clear();
  }

#if __LP64__
  char *linker_path = (char *)"/system/bin/linker64";
#else
  char *linker_path = (char *)"/system/bin/linker";
#endif

  static soinfo_t (*solist_get_head)() = NULL;
  if (!solist_get_head)
    solist_get_head = (soinfo_t (*)())resolve_elf_internal_symbol(linker_path, "__dl__Z15solist_get_headv");

  static soinfo_t (*solist_get_somain)() = NULL;
  if (!solist_get_somain)
    solist_get_somain = (soinfo_t (*)())resolve_elf_internal_symbol(linker_path, "__dl__Z17solist_get_somainv");

  static addr_t *solist_head = NULL;
  if (!solist_head)
    solist_head = (addr_t *)solist_get_head();

  static addr_t somain = 0;
  if (!somain)
    somain = (addr_t)solist_get_somain();

    // Generate the name for an offset.
#define PARAM_OFFSET(type_, member_) __##type_##__##member_##__offset_
#define STRUCT_OFFSET PARAM_OFFSET
  int STRUCT_OFFSET(solist, next) = 0;
  for (size_t i = 0; i < 16; i++) {
    if (*(addr_t *)((addr_t)solist_head + i * 8) == somain) {
      STRUCT_OFFSET(solist, next) = i * 8;
      break;
    }
  }

  linker_solist.push_back(solist_head);

  addr_t sonext = 0;
  sonext        = *(addr_t *)((addr_t)solist_head + STRUCT_OFFSET(solist, next));
  while (sonext) {
    linker_solist.push_back((void *)sonext);
    sonext = *(addr_t *)((addr_t)sonext + STRUCT_OFFSET(solist, next));
  }

  return linker_solist;
}

char *linker_soinfo_get_realpath(soinfo_t soinfo) {
  static char *(*_get_realpath)(soinfo_t) = NULL;
  if (!_get_realpath)
    _get_realpath = (char *(*)(soinfo_t))resolve_elf_internal_symbol("linker64", "__dl__ZNK6soinfo12get_realpathEv");
  return _get_realpath(soinfo);
}

void linker_iterate_soinfo(int (*cb)(soinfo_t soinfo)) {
  auto solist = linker_get_solist();
  for (auto it = solist.begin(); it != solist.end(); it++) {
    int ret = cb(*it);
    if (ret != 0)
      break;
  }
}