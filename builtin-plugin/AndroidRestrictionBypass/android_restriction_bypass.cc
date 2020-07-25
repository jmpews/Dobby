#include <elf.h>
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>

#include <unordered_map>
#include <vector>

#include <android/log.h>
#define LOG_TAG "DobbyExample"
#define LOG(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

typedef uintptr_t addr_t;

//static std::unordered_map<uintptr_t, soinfo*>* g_soinfo_handles_map = nullptr;

void *trick_dlopen(const char *filename, int flag) {
  typedef void *(*__loader_dlopen_t)(const char *filename, int flags, const void *caller_addr);
  __loader_dlopen_t __loader_dlopen = NULL;

  void *dl        = dlopen("libdl.so", RTLD_LAZY);
  __loader_dlopen = (__loader_dlopen_t)dlsym(dl, "__loader_dlopen");

  return __loader_dlopen(filename, flag, (void *)__loader_dlopen);
}
//  void *handle = trick_dlopen("/apex/com.android.runtime/bin/linker64", RTLD_LAZY);

__attribute__((constructor)) void init_android_restriction_bypass() {
//  DobbySymbolResolver("/apex/com.android.runtime/lib64/bionic/libdl.so", "__dl_g_soinfo_handles_map");
}
