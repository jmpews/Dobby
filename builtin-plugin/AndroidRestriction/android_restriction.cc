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

#include "dobby.h"
#include "dobby_symbol_resolver.h"

#include "common/headers/common_header.h"

// impl at "dobby_symbol_resolver.cc"
extern void *resolve_elf_internal_symbol(const char *library_name, const char *symbol_name);

#if __LP64__
const char *LINKER_PATH = (char *)"/system/bin/linker64";
#else
const char *LINKER_PATH = (char *)"/system/bin/linker";
#endif

void *linker_dlopen(const char *filename, int flag) {
  typedef void *(*__loader_dlopen_t)(const char *filename, int flags, const void *caller_addr);
  static __loader_dlopen_t __loader_dlopen = NULL;
  if (!__loader_dlopen)
    __loader_dlopen = (__loader_dlopen_t)DobbySymbolResolver(NULL, "__loader_dlopen");

  // fake caller address
  return __loader_dlopen(filename, flag, (void *)open);
}

std::vector<soinfo_t> linker_solist;
std::vector<soinfo_t> linker_get_solist() {
  if (!linker_solist.empty()) {
    linker_solist.clear();
  }

  static soinfo_t (*solist_get_head)() = NULL;
  if (!solist_get_head)
    solist_get_head = (soinfo_t(*)())resolve_elf_internal_symbol(LINKER_PATH, "__dl__Z15solist_get_headv");

  static soinfo_t (*solist_get_somain)() = NULL;
  if (!solist_get_somain)
    solist_get_somain = (soinfo_t(*)())resolve_elf_internal_symbol(LINKER_PATH, "__dl__Z17solist_get_somainv");

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
    _get_realpath = (char *(*)(soinfo_t))resolve_elf_internal_symbol(LINKER_PATH, "__dl__ZNK6soinfo12get_realpathEv");
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
typedef void *android_namespace_t;
android_namespace_t linker_soinfo_get_primary_namespace(soinfo_t soinfo) {
  static android_namespace_t (*_get_primary_namespace)(soinfo_t) = NULL;
  if (!_get_primary_namespace)
    _get_primary_namespace = (android_namespace_t(*)(soinfo_t))resolve_elf_internal_symbol(
        LINKER_PATH, "__dl__ZN6soinfo21get_primary_namespaceEv");
  return _get_primary_namespace(soinfo);
}

static int iterate_soinfo_cb(soinfo_t soinfo) {
  android_namespace_t ns = NULL;
  ns                     = linker_soinfo_get_primary_namespace(soinfo);
  DLOG("lib: %s", linker_soinfo_get_realpath(soinfo));

  // set is_isolated_ as false
  *(uint8_t *)((addr_t)ns + 0x8) = false;

  if(*(void **)((addr_t)ns + 0x10)) {
    LOG("lib already hack");
  }
  std::vector<std::string> ld_library_paths        = {"/system/lib64", "/sytem/lib"};
  *(std::vector<std::string> *)((addr_t)ns + 0x10) = std::move(ld_library_paths);

  return 0;
}

bool (*orig_linker_namespace_is_is_accessible)(android_namespace_t ns, const std::string &file);
bool linker_namespace_is_is_accessible(android_namespace_t ns, const std::string &file) {
  LOG("check %s", file.c_str());
  return true;
  return orig_linker_namespace_is_is_accessible(ns, file);
}

void linker_disable_namespace_restriction() {
  linker_iterate_soinfo(iterate_soinfo_cb);

//  void *linker_namespace_is_is_accessible_ptr =
//      resolve_elf_internal_symbol(LINKER_PATH, "__dl__ZN19android_namespace_t13is_accessibleERKNSt3__112basic_"
//                                               "stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE");
//  DobbyHook(linker_namespace_is_is_accessible_ptr, (void *)linker_namespace_is_is_accessible,
//            (void **)&orig_linker_namespace_is_is_accessible);

  LOG("disable namespace restriction done");
}