#ifndef PLATFORM_THREAD_H_
#define PLATFORM_THREAD_H_

#include <cstdarg>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <iostream>

#include "UnifiedInterface/StdMemory.h"

namespace zz {

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

  static bool HasThreadLocal(LocalStorageKey key) {
    return GetThreadLocal(key) != nullptr;
  }

  static inline void *GetExistingThreadLocal(LocalStorageKey key) {
    return GetThreadLocal(key);
  }
};

} // namespace zz

#endif