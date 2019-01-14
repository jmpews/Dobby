#ifndef ZZ_PLATFORM_PLATFORM_H_
#define ZZ_PLATFORM_PLATFORM_H_

#include <cstdarg>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>


#include <iostream>

namespace zz {

class OSPrint {
public:
  // Print output to console. This is mostly used for debugging output.
  // On platforms that has standard terminal output, the output
  // should go to stdout.
  static void Print(const char *format, ...);

  static void VPrint(const char *format, va_list args);

  // Print output to a file. This is mostly used for debugging output.
  static void FPrint(FILE *out, const char *format, ...);

  static void VFPrint(FILE *out, const char *format, va_list args);

  // Print error output to console. This is mostly used for error message
  // output. On platforms that has standard terminal output, the output
  // should go to stderr.
  static void PrintError(const char *format, ...);

  static void VPrintError(const char *format, va_list args);
};

class OSMemory {
public:
  // ===

  struct SharedLibraryAddress {
    SharedLibraryAddress(const std::string &library_path, uintptr_t start, uintptr_t end)
        : library_path(library_path), start(start), end(end), aslr_slide(0) {}
    SharedLibraryAddress(const std::string &library_path, uintptr_t start, uintptr_t end, intptr_t aslr_slide)
        : library_path(library_path), start(start), end(end), aslr_slide(aslr_slide) {}

    std::string library_path;
    uintptr_t start;
    uintptr_t end;
    intptr_t aslr_slide;
  };

  static std::vector<SharedLibraryAddress> GetSharedLibraryAddresses();

  struct MemoryRegion {
    MemoryRegion(uintptr_t start, uintptr_t end, MemoryPermission permission)
        : start(start), end(end), permission(permission) {}
    uintptr_t start;
    uintptr_t end;
    MemoryPermission permission;
  };

  static std::vector<MemoryRegion> GetMemoryLayout();

  static size_t PageSize();

  static void *Allocate(void *address, size_t size, size_t alignment, MemoryPermission access);

  static bool Free(void *address, const size_t size);

  static bool Release(void *address, size_t size);

  static bool SetPermissions(void *address, size_t size, MemoryPermission access);
};

class OSThread {
public:
  typedef int32_t LocalStorageKey;

  static int GetCurrentProcessId();

  static int GetCurrentThreadId();

  // Thread-local storage.
  static LocalStorageKey CreateThreadLocalKey();

  static void DeleteThreadLocalKey(LocalStorageKey key);

  static void *GetThreadLocal(LocalStorageKey key);

  static int GetThreadLocalInt(LocalStorageKey key) {
    return static_cast<int>(reinterpret_cast<intptr_t>(GetThreadLocal(key)));
  }

  static void SetThreadLocal(LocalStorageKey key, void *value);

  static void SetThreadLocalInt(LocalStorageKey key, int value) {
    SetThreadLocal(key, reinterpret_cast<void *>(static_cast<intptr_t>(value)));
  }

  static bool HasThreadLocal(LocalStorageKey key) { return GetThreadLocal(key) != nullptr; }

  static inline void *GetExistingThreadLocal(LocalStorageKey key) { return GetThreadLocal(key); }
};

} // namespace zz

#endif
