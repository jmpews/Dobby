#include "HookCc.h"

/* ===== System-Detect ===== */
#if defined(_M_X64) || defined(__x86_64__)
#define TARGET_ARCH_X64 1
#elif defined(_M_IX86) || defined(__i386__)
#define TARGET_ARCH_IA32 1
#elif defined(__AARCH64EL__)
#define TARGET_ARCH_ARM64 1
#elif defined(__ARMEL__)
#define TARGET_ARCH_ARM 1
#else
#error Target architecture was not detected as supported by HookCc
#endif

/* ===== OS-detection ===== */
#if defined(__ANDROID__)
// Check for Android first, to determine its difference from Linux.
#define HOST_OS_ANDROID 1
#elif defined(__linux__) || defined(__FreeBSD__)
// Generic Linux.
#define HOST_OS_LINUX 1
#elif defined(__APPLE__)
// Define the flavor of Mac OS we are running on.
#include <TargetConditionals.h>
// TODO(iposva): Rename HOST_OS_MACOS to HOST_OS_MAC to inherit
// the value defined in TargetConditionals.h
#define HOST_OS_MACOS 1
#if TARGET_OS_IPHONE
#define HOST_OS_IOS 1
#endif
#elif defined(_WIN32)
// Windows, both 32- and 64-bit, regardless of the check for _WIN32.
#define HOST_OS_WINDOWS 1
#else
#error Target architecture was not detected as supported by HookCc
#endif

/* ===== PreProcessor ===== */

#if !defined(HOST_OS_WINDOWS)
#define HOST_OS_POSIX
#endif //! !defined(HOST_OS_WINDOWS)

/* ===== User-Register-Method ===== */

#ifdef USE_OWN_REGISTER_METHOD

struct _RegisterCoreMethod {
  void *(*alloc_exec_chunk)(int);

  void *(*patch_exec_memory)(void *, void *, int);

  void (*debug_log)(const char *fmt, ...);
};

struct _RegisterCoreMethod RegisterCoreMethod;

void *register_alloc_exec_chunk(void *func) {
  RegisterCoreMethod.alloc_exec_chunk = func;
}

void *register_patch_exec_memory(void *func) {
  RegisterCoreMethod.patch_exec_memory = func;
}

void *register_debug_log(void *func) {
  RegisterCoreMethod.debug_log = func;
}

#endif // USE_OWN_REGISTER_METHOD

/* ===== System-Depent-Header ===== */
#if !defined(USE_OWN_REGISTER_METHOD)
#if !defined(HOST_OS_WINDOWS)

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif //! defined(__APPLE__)

#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
#define LOG_TAG "HookCc"
#include <android/log.h>
#endif //! defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)

#endif //! !defined(HOST_OS_WINDOWS)

/* ===== Platform-API =====*/

// normal alloc
void *cc_mem_alloc(int size);

// get memory page size
int cc_mem_get_page_size();

// alloc executable page
void *cc_mem_alloc_exec_page();

// alloc executable memory chunk
void *cc_mem_alloc_exec_chunk(int size);

// set page permission
void *cc_mem_set_page_permission(void *page_address, MemoryPermission permission);

// patch executable memory
void cc_mem_patch_exec_memory(void *dest, void *src, int size);

#if !defined(HOST_OS_WINDOWS)

enum MemoryPermission { kNoAccess, kRead, kReadWrite, kReadWriteExecute, kReadExecute };
#if defined(__APPLE__)
const int kMmapFd = VM_MAKE_TAG(255);
#else
const int kMmapFd = -1;
#endif //! defined(__APPLE__)

#define mmap_flags (MAP_PRIVATE | MAP_ANONYMOUS);
#define mem_rx_prot (PROT_READ | PROT_EXEC)
#define mem_rw_prot (PROT_READ | PROT_WRITE)
#define mem_rwx_prot (PROT_READ | PROT_WRITE | PROT_EXEC)

const int kMmapFdOffset = 0;

struct list_head {
  struct list_head *next, *prev;
};

struct ExecPageChunk {
  struct list_head *head;
  void *address;
  void *cursor;
  int capacity;
};

struct ExecPageChunk *ExecPageChunkHead    = NULL;
struct ExecPageChunk *ExecPageChunkCurrent = NULL;

int cc_mem_get_page_size() {
  return sysconf(_SC_PAGESIZE);
}

void *cc_mem_alloc_exec_page() {
  void *address = NULL;
  int page_size = cc_mem_get_page_size();
  void *result  = mmap(address, page_size, mem_rx_prot, mmap_flags, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED)
    return NULL;
}

void *cc_mem_alloc_exec_chunk(int *ioSize) {
  if (!ExecPageChunkHead) {
    ExecPageChunk *page_chunk = cc_mem_alloc(sizeof(ExecPageChunk));
    page_chunk->capacity      = cc_mem_get_page_size();
    page_chunk->address       = cc_mem_alloc_exec_page();
    page_chunk->cursor        = page_chunk->address;
    page_chunk->head.next     = NULL;
    ExecPageChunkHead         = page_chunk;
    ExecPageChunkCurrent      = ExecPageChunkHead;
  }

  void *result = NULL;

// No Need to iter the list, because the ExecPageChunk NOT release
#if 0
  // iterator the ExecPageChunk List
  ExecPageChunk *iter = ExecPageChunkHead;
  do {
    int len = (addr_t)iter->cursor - (addr_t)iter->address;
    if (iter->capacity > (len + *ioSize)) {
      result       = iter->cursor;
      iter->cursor = (void *)((addr_t)iter->cursor + ioSize);
      return result;
    }

    iter = iter->head.next;
  } while (iter);
#endif

  int len = (addr_t)ExecPageChunkCurrent->cursor - (addr_t)ExecPageChunkCurrent->address;
  if (ExecPageChunkCurrent->capacity < (len + *ioSize)) {
    ExecPageChunk *page_chunk = cc_mem_alloc(sizeof(ExecPageChunk));
    page_chunk->capacity      = cc_mem_get_page_size();
    page_chunk->address       = cc_mem_alloc_exec_page();
    page_chunk->cursor        = page_chunk->address;
    page_chunk->head.next     = ExecPageChunkCurrent;
    ExecPageChunkCurrent      = page_chunk;
  }

  result                       = ExecPageChunkCurrent->cursor;
  ExecPageChunkCurrent->cursor = (void *)((addr_t)iter->ExecPageChunkCurrent + *ioSize);
  return result;
}

int cc_mem_set_page_permission(void *page_address, MemoryPermission permission) {
  int ret;
  if (permission == kReadWrite)
    ret = mprotect(page_address, cc_mem_get_page_size(), mem_rw_prot);
  else if (permission == kReadExecute)
    ret = mprotect(page_address, cc_mem_get_page_size(), mem_rx_prot);
  else if (permission == kReadWriteExecute)
    ret = mprotect(page_address, cc_mem_get_page_size(), mem_rwx_prot);
  return ret;
}

void cc_mem_patch_exec_memory(void *dest, void *src, int size) {
}

#endif
#endif