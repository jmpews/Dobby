#include "macros.h"
#include "logging/check_logging.h"
#include "PlatformInterface/platform.h"

#include "UnifiedInterface/StdMemory.h"

namespace zz {

int GetProtectionFromMemoryPermission(MemoryPermission access) {
  return 0;
}

int GetFlagsForMemoryPermission(MemoryPermission access) {
  int flags = 0;
  return flags;
}

void *Allocate(void *address, size_t size, MemoryPermission access) {
  int prot     = GetProtectionFromMemoryPermission(access);
  int flags    = GetFlagsForMemoryPermission(access);
  return nullptr;
}

// static
size_t OSMemory::PageSize() {
  return 0;
}

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
  DCHECK_EQ(0, 0);
  return 0;
}

// static
bool OSMemory::Release(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  return 0;
}

// static
bool OSMemory::SetPermissions(void *address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  return 0;
}

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

int OSThread::GetCurrentProcessId() {
  return 0;
}

int OSThread::GetCurrentThreadId() {
  return 0;
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
