#ifndef ZZ_PLATFORM_PLATFORM_H_
#define ZZ_PLATFORM_PLATFORM_H_

#include <cstdarg>
#include <string>
#include <vector>
#include <stdio.h>

#include "vm_core/macros.h"

namespace zz {

class PageAllocator;

class OS {
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

  static int GetCurrentProcessId();

  static int GetCurrentThreadId();

  enum class MemoryPermission { kNoAccess, kRead, kReadWrite, kReadWriteExecute, kReadExecute };

private:
  friend class PageAllocator;

  static size_t PageSize();

  static void *Allocate(void *address, size_t size, size_t alignment, MemoryPermission access);

  static bool Free(void *address, const size_t size);

  static bool Release(void *address, size_t size);

  static bool SetPermissions(void *address, size_t size, MemoryPermission access);
};

class Thread {
public:
  typedef int32_t LocalStorageKey;

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

  static bool HasThreadLocal(LocalStorageKey key) {
    return GetThreadLocal(key) != nullptr;
  }

  static inline void *GetExistingThreadLocal(LocalStorageKey key) {
    return GetThreadLocal(key);
  }
};

} // namespace zz

#endif
