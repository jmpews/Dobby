#include <errno.h>
#include <limits.h>
#include <pthread.h>
#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <pthread_np.h> // for pthread_set_name_np
#endif
#include <sched.h> // for sched_yield
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h> // NOLINT, for sysctl
#endif

#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
#define LOG_TAG "zzzzz"
#include <android/log.h> // NOLINT
#endif

#include "macros.h"
#include "logging/check_logging.h"
#include "platform/platform.h"

#include "UnifiedInterface/StdMemory.h"

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

namespace zz {

#if defined(__APPLE__)
const int kMmapFd = VM_MAKE_TAG(255);
#else
const int kMmapFd = -1;
#endif

const int kMmapFdOffset = 0;

int GetProtectionFromMemoryPermission(MemoryPermission access) {
  switch (access) {
  case MemoryPermission::kNoAccess:
    return PROT_NONE;
  case MemoryPermission::kRead:
    return PROT_READ;
  case MemoryPermission::kReadWrite:
    return PROT_READ | PROT_WRITE;
  case MemoryPermission::kReadWriteExecute:
    return PROT_READ | PROT_WRITE | PROT_EXEC;
  case MemoryPermission::kReadExecute:
    return PROT_READ | PROT_EXEC;
  }
  UNREACHABLE();
}

int GetFlagsForMemoryPermission(MemoryPermission access) {
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (access == MemoryPermission::kNoAccess) {
  }
  return flags;
}

void *Allocate(void *address, size_t size, MemoryPermission access) {
  int prot     = GetProtectionFromMemoryPermission(access);
  int flags    = GetFlagsForMemoryPermission(access);
  void *result = mmap(address, size, prot, flags, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED)
    return nullptr;
  return result;
}

// static
size_t OSMemory::PageSize() { return static_cast<size_t>(sysconf(_SC_PAGESIZE)); }

// static
void *OSMemory::Allocate(void *address, size_t size, MemoryPermission access) {
  size_t page_size = OSMemory::PageSize();
  size_t request_size = size;
  void *result        = zz::Allocate(address, request_size, access);
  if (result == nullptr)
    return nullptr;

  // TODO: if need align

  void *aligned_base = result;
  return static_cast<void *>(aligned_base);
}

// static
bool OSMemory::Free(void *address, const size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  return munmap(address, size) == 0;
}

// static
bool OSMemory::Release(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  return munmap(address, size) == 0;
}

// static
bool OSMemory::SetPermissions(void *address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  int ret  = mprotect(address, size, prot);
  if (ret == 0 && access == MemoryPermission::kNoAccess) {
    // This is advisory; ignore errors and continue execution.
    // ReclaimInaccessibleMemory(address, size);
  }

  if (ret) {
    DLOG("[!] %s\n", ((const char *)strerror(errno)));
  }

// For accounting purposes, we want to call MADV_FREE_REUSE on macOS after
// changing permissions away from MemoryPermission::kNoAccess. Since this
// state is not kept at this layer, we always call this if access != kNoAccess.
// The cost is a syscall that effectively no-ops.
// TODO(erikchen): Fix this to only call MADV_FREE_REUSE when necessary.
// https://crbug.com/823915
#if defined(OS_MACOSX)
  if (access != MemoryPermission::kNoAccess)
    madvise(address, size, MADV_FREE_REUSE);
#endif

  return ret == 0;
}

// ======

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vprintf(format, args);
#endif
}

void OSPrint::FPrint(FILE *out, const char *format, ...) {
  va_list args;
  va_start(args, format);
  VFPrint(out, format, args);
  va_end(args);
}

void OSPrint::VFPrint(FILE *out, const char *format, va_list args) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vfprintf(out, format, args);
#endif
}

void OSPrint::PrintError(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrintError(format, args);
  va_end(args);
}

void OSPrint::VPrintError(const char *format, va_list args) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, format, args);
#else
  vfprintf(stderr, format, args);
#endif
}

// =====

int OSThread::GetCurrentProcessId() { return static_cast<int>(getpid()); }

int OSThread::GetCurrentThreadId() {
#if defined(__APPLE__)
  return static_cast<int>(pthread_mach_thread_np(pthread_self()));
#elif defined(__ANDROID__)
  return static_cast<int>(gettid());
#elif defined(__linux__)
  return static_cast<int>(syscall(__NR_gettid));
#else
  return static_cast<int>(reinterpret_cast<intptr_t>(pthread_self()));
#endif
}

OSThread::LocalStorageKey OSThread::CreateThreadLocalKey() {
  return 0;
}

void OSThread::DeleteThreadLocalKey(LocalStorageKey key) {
  return;
}

void *OSThread::GetThreadLocal(LocalStorageKey key) {
  return NULL;
}

void OSThread::SetThreadLocal(LocalStorageKey key, void *value) {
  return;
}

} // namespace zz
