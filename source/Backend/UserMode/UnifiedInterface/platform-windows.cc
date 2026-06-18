#include <stdio.h>
#include <windows.h>
#include "logging/logging.h"
#include "logging/check_logging.h"
#include "PlatformUnifiedInterface/platform.h"

static int GetProtectionFromMemoryPermission(MemoryPermission access) {
  if (kReadWriteExecute == access)
    return PAGE_EXECUTE_READWRITE;
  else if (kReadExecute == access)
    return PAGE_EXECUTE_READ;
  return PAGE_NOACCESS;
}

int OSMemory::PageSize() {
  static int lastRet = -1;
  if (lastRet == -1) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    lastRet = si.dwPageSize;
  }
  return lastRet;
}

void *OSMemory::Allocate(size_t size, MemoryPermission access, void *fixed_addr) {
  void *result = VirtualAlloc(fixed_addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
  if (result == nullptr)
    return nullptr;
  OSMemory::SetPermission(result, size, access);
  return result;
}

void *OSMemory::Allocate(size_t size, MemoryPermission access) {
  return OSMemory::Allocate(size, access, nullptr);
}

bool OSMemory::Free(void *address, size_t size) {
  return VirtualFree(address, 0, MEM_RELEASE);
}

bool OSMemory::Release(void *address, size_t size) {
  return OSMemory::Free(address, size);
}

bool OSMemory::SetPermission(void *address, size_t size, MemoryPermission access) {
  int prot = GetProtectionFromMemoryPermission(access);
  DWORD oldProtect;
  return VirtualProtect(address, size, prot, &oldProtect);
}

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
  vprintf(format, args);
}