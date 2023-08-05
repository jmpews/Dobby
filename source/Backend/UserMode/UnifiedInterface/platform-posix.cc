#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>

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
#include <sys/syscall.h>

#if defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h> // NOLINT, for sysctl
#endif

#include "logging/logging.h"
#include "logging/check_logging.h"
#include "PlatformUnifiedInterface/platform.h"

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#endif

#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
#define ANDROID_LOG_TAG "Dobby"

#include <android/log.h>

#endif

#include <string.h>

#if defined(__APPLE__)
const int kMmapFd = VM_MAKE_TAG(255);
#else
const int kMmapFd = -1;
#endif

const int kMmapFdOffset = 0;

using namespace base;

typedef struct thread_handle_t {
  pthread_t thread;
} thread_handle_t;

void ThreadInterface::SetName(const char *name) {
#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  pthread_set_name_np(pthread_self(), name);
#elif defined(__APPLE__)
  pthread_setname_np(name);
#endif
}

int ThreadInterface::CurrentId() {
#if defined(__APPLE__)
  mach_port_t port = mach_thread_self();
  mach_port_deallocate(mach_task_self(), port);
  return port;
#elif defined(_POSIX_VERSION)
  return syscall(__NR_gettid);
#endif
}

void *ThreadInterface::thread_handler_wrapper(Delegate *ctx) {
  auto d = (ThreadInterface::Delegate *)ctx;
  d->ThreadMain();
  return nullptr;
}

bool ThreadInterface::Create(ThreadInterface::Delegate *delegate) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);

  auto handle_impl = new thread_handle_t();
  auto err = pthread_create(&(handle_impl->thread), &attr, (void *(*)(void *))thread_handler_wrapper, delegate);
  if (err != 0) {
    ERROR_LOG("pthread create failed");
    return false;
  }
  this->handle = handle_impl;
  return true;
}

OSThread::OSThread(const char *in_name) {
  strncpy(name, in_name, sizeof(name));
}

OSThread::OSThread(const char *in_name, uint32_t in_stack_size) {
  strncpy(name, in_name, sizeof(name));
  stack_size = in_stack_size;
}

bool OSThread::Start() {
  return ThreadInterface::Create(this);
}

// --- memory

static int GetProtectionFromMemoryPermission(MemoryPermission access) {
  int prot = 0;
  if (access & MemoryPermission::kRead)
    prot |= PROT_READ;
  if (access & MemoryPermission::kWrite)
    prot |= PROT_WRITE;
  if (access & MemoryPermission::kExecute)
    prot |= PROT_EXEC;
  return prot;
}

int OSMemory::PageSize() {
  return static_cast<int>(sysconf(_SC_PAGESIZE));
}

void *OSMemory::Allocate(size_t size, MemoryPermission access) {
  return OSMemory::Allocate(size, access, nullptr);
}

void *OSMemory::Allocate(size_t size, MemoryPermission access, void *fixed_address) {
  int prot = GetProtectionFromMemoryPermission(access);

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (fixed_address != nullptr) {
    flags = flags | MAP_FIXED;
  }
  void *result = mmap(fixed_address, size, prot, flags, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED)
    return nullptr;

  return result;
}

bool OSMemory::Free(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  return munmap(address, size) == 0;
}

bool OSMemory::Release(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  return munmap(address, size) == 0;
}

bool OSMemory::SetPermission(void *address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  int ret = mprotect(address, size, prot);
  if (ret) {
    ERROR_LOG("OSMemory::SetPermission: %s", ((const char *)strerror(errno)));
  }

  return ret == 0;
}

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, ANDROID_LOG_TAG, format, args);
#else
  vprintf(format, args);
#endif
}
