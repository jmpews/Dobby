#pragma once

#include "dobby/common.h"

namespace base {

class ThreadLocalStorageInterface {
  using LocalStorageKey = int32_t;

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
};

typedef void *ThreadHandle;

struct ThreadInterface {
  base::ThreadHandle handle;
  int id = 0;
  char name[256] = {0};
  uint32_t stack_size = 4 * 1024 * 1024;

  struct Delegate {
    [[noreturn]] virtual void ThreadMain() = 0;
  };

  bool Create(Delegate *delegate);

  static int CurrentId();

  static void SetName(const char *);

  static void *thread_handler_wrapper(Delegate *ctx);
};
} // namespace base

struct OSThread : base::ThreadInterface, base::ThreadInterface::Delegate {
  OSThread(const char *name);

  OSThread(const char *name, uint32_t stack_size);

  bool Start();
};

enum MemoryPermission {
  kNoAccess,
  kRead = 1,
  kWrite = 2,
  kExecute = 4,
  kReadWrite = kRead | kWrite,
  kReadExecute = kRead | kExecute,
  kReadWriteExecute = kRead | kWrite | kExecute,
};

class OSMemory {
public:
  static int PageSize();

  static void *Allocate(size_t size, MemoryPermission access);

  static void *Allocate(size_t size, MemoryPermission access, void *fixed_addr);

  static bool Free(void *address, size_t size);

  static bool Release(void *address, size_t size);

  static bool SetPermission(void *address, size_t size, MemoryPermission access);
};

class OSPrint {
public:
  static void Print(const char *format, ...);

  static void VPrint(const char *format, va_list args);
};