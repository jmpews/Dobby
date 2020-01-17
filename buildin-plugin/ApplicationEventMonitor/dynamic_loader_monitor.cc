#include <stdlib.h> /* getenv */
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <fstream>

#include <set>
#include <unordered_map>

#include "./dobby_monitor.h"

#include <dlfcn.h>
#include <sys/param.h>

std::unordered_map<void *, const char *> traced_dlopen_handle_list;

void *(*orig_dlopen)(const char *__file, int __mode);
void *fake_dlopen(const char *__file, int __mode) {

  void *result = orig_dlopen(__file, __mode);
  if (result != NULL) {
    char *traced_filename = (char *)malloc(MAXPATHLEN);
    // FIXME: strncpy
    strcpy(traced_filename, __file);
    std::cout << "[-] trace handle: " << __file << std::endl;
    traced_dlopen_handle_list.insert(std::make_pair(result, (const char *)traced_filename));
  }
  return result;
}

static const char *get_traced_filename(void *handle, bool removed) {
  std::unordered_map<void *, const char *>::iterator it;
  it = traced_dlopen_handle_list.find(handle);
  if (it != traced_dlopen_handle_list.end()) {
    if (removed)
      traced_dlopen_handle_list.erase(it);
    return it->second;
  }
  return NULL;
}

void *(*orig_dlsym)(void *__handle, const char *__symbol);
void *fake_dlsym(void *__handle, const char *__symbol) {
  const char *traced_filename = get_traced_filename(__handle, false);
  if (traced_filename) {
    LOG("[-] dlsym: %s, symbol: %s\n", traced_filename, __symbol);
  }
  return orig_dlsym(__handle, __symbol);
}

int (*orig_dlclose)(void *__handle);
int fake_dlclose(void *__handle) {
  const char *traced_filename = get_traced_filename(__handle, true);
  if (traced_filename) {
    LOG("[-] dlclose: %s\n", traced_filename);
    free((void *)traced_filename);
  }
  return orig_dlclose(__handle);
}

__attribute__((constructor)) static void ctor() {
  DobbyHook((void *)dlopen, (void *)fake_dlopen, (void **)&orig_dlopen);
  DobbyHook((void *)dlsym, (void *)fake_dlsym, (void **)&orig_dlsym);
  DobbyHook((void *)dlclose, (void *)fake_dlclose, (void **)&orig_dlclose);
}