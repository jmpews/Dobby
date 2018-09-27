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

#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
#define LOG_TAG "zz"
#include <android/log.h> // NOLINT
#endif

#include "vm_core/platform/platform-posix.h"
#include "vm_core/platform/platform.h"
#include "vm_core/macros.h"
#include "vm_core/logging.h"

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

namespace zz {

// =====

#if defined(__APPLE__)
const int kMmapFd = VM_MAKE_TAG(255);
#else
const int kMmapFd = -1;
#endif

const int kMmapFdOffset = 0;

int GetProtectionFromMemoryPermission(OS::MemoryPermission access) {
  switch (access) {
  case OS::MemoryPermission::kNoAccess:
    return PROT_NONE;
  case OS::MemoryPermission::kRead:
    return PROT_READ;
  case OS::MemoryPermission::kReadWrite:
    return PROT_READ | PROT_WRITE;
  case OS::MemoryPermission::kReadWriteExecute:
    return PROT_READ | PROT_WRITE | PROT_EXEC;
  case OS::MemoryPermission::kReadExecute:
    return PROT_READ | PROT_EXEC;
  }
  UNREACHABLE();
}

int GetFlagsForMemoryPermission(OS::MemoryPermission access) {
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (access == OS::MemoryPermission::kNoAccess) {
  }
  return flags;
}

void *Allocate(void *address, size_t size, OS::MemoryPermission access) {
  int prot     = GetProtectionFromMemoryPermission(access);
  int flags    = GetFlagsForMemoryPermission(access);
  void *result = mmap(address, size, prot, flags, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED)
    return nullptr;
  return result;
}

// static
size_t OS::PageSize() {
  return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}

// static
void *OS::Allocate(void *address, size_t size, size_t alignment, MemoryPermission access) {
  size_t page_size = OS::PageSize();
  DCHECK_EQ(0, size % page_size);
  DCHECK_EQ(0, alignment % page_size);
  size_t request_size = size;
  void *result        = zz::Allocate(address, request_size, access);
  if (result == nullptr)
    return nullptr;

  // TODO: if need align

  void *aligned_base = result;
  return static_cast<void *>(aligned_base);
}

// static
bool OS::Free(void *address, const size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  return munmap(address, size) == 0;
}

// static
bool OS::Release(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  return munmap(address, size) == 0;
}

// static
bool OS::SetPermissions(void *address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  int ret  = mprotect(address, size, prot);
  if (ret == 0 && access == OS::MemoryPermission::kNoAccess) {
    // This is advisory; ignore errors and continue execution.
    // ReclaimInaccessibleMemory(address, size);
  }

// For accounting purposes, we want to call MADV_FREE_REUSE on macOS after
// changing permissions away from OS::MemoryPermission::kNoAccess. Since this
// state is not kept at this layer, we always call this if access != kNoAccess.
// The cost is a syscall that effectively no-ops.
// TODO(erikchen): Fix this to only call MADV_FREE_REUSE when necessary.
// https://crbug.com/823915
#if defined(OS_MACOSX)
  if (access != OS::MemoryPermission::kNoAccess)
    madvise(address, size, MADV_FREE_REUSE);
#endif

  return ret == 0;
}

// ======

int OS::GetCurrentProcessId() {
  return static_cast<int>(getpid());
}

int OS::GetCurrentThreadId() {
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

// =====

void OS::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OS::VPrint(const char *format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vprintf(format, args);
#endif
}

void OS::FPrint(FILE *out, const char *format, ...) {
  va_list args;
  va_start(args, format);
  VFPrint(out, format, args);
  va_end(args);
}

void OS::VFPrint(FILE *out, const char *format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vfprintf(out, format, args);
#endif
}

void OS::PrintError(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrintError(format, args);
  va_end(args);
}

void OS::VPrintError(const char *format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, format, args);
#else
  vfprintf(stderr, format, args);
#endif
}

// =====

static Thread::LocalStorageKey PthreadKeyToLocalKey(pthread_key_t pthread_key) {
#if defined(__cygwin__)
  // We need to cast pthread_key_t to Thread::LocalStorageKey in two steps
  // because pthread_key_t is a pointer type on Cygwin. This will probably not
  // work on 64-bit platforms, but Cygwin doesn't support 64-bit anyway.
  assert(sizeof(Thread::LocalStorageKey) == sizeof(pthread_key_t));
  intptr_t ptr_key = reinterpret_cast<intptr_t>(pthread_key);
  return static_cast<Thread::LocalStorageKey>(ptr_key);
#else
  return static_cast<Thread::LocalStorageKey>(pthread_key);
#endif
}

static pthread_key_t LocalKeyToPthreadKey(Thread::LocalStorageKey local_key) {
#if defined(__cygwin__)
  assert(sizeof(Thread::LocalStorageKey) == sizeof(pthread_key_t));
  intptr_t ptr_key = static_cast<intptr_t>(local_key);
  return reinterpret_cast<pthread_key_t>(ptr_key);
#else
  return static_cast<pthread_key_t>(local_key);
#endif
}

Thread::LocalStorageKey Thread::CreateThreadLocalKey() {
  pthread_key_t key;
  int result = pthread_key_create(&key, nullptr);
  DCHECK_EQ(0, result);
  LocalStorageKey local_key = PthreadKeyToLocalKey(key);
  return local_key;
}

void Thread::DeleteThreadLocalKey(LocalStorageKey key) {
  pthread_key_t pthread_key = LocalKeyToPthreadKey(key);
  int result                = pthread_key_delete(pthread_key);
  DCHECK_EQ(0, result);
}

void *Thread::GetThreadLocal(LocalStorageKey key) {
  pthread_key_t pthread_key = LocalKeyToPthreadKey(key);
  return pthread_getspecific(pthread_key);
}

void Thread::SetThreadLocal(LocalStorageKey key, void *value) {
  pthread_key_t pthread_key = LocalKeyToPthreadKey(key);
  int result                = pthread_setspecific(pthread_key, value);
  DCHECK_EQ(0, result);
}

// =====
}
