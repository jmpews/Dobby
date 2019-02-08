#ifndef PLATFORM_THREAD_H_
#define PLATFORM_THREAD_H_

#include "KernelOrUser.h"

#include "UnifiedInterface/StdMemory.h"

namespace zz {

class OSThread {
public:
  typedef int LocalStorageKey;

  static int GetCurrentProcessId();

  static int GetCurrentThreadId();

  // Thread-local storage.
  static LocalStorageKey CreateThreadLocalKey();

  static void DeleteThreadLocalKey(LocalStorageKey key);

  static void *GetThreadLocal(LocalStorageKey key);

  static int GetThreadLocalInt(LocalStorageKey key);

  static void SetThreadLocal(LocalStorageKey key, void *value);

  static void SetThreadLocalInt(LocalStorageKey key, int value);

  static bool HasThreadLocal(LocalStorageKey key);

  static void *GetExistingThreadLocal(LocalStorageKey key);
};

} // namespace zz

#endif