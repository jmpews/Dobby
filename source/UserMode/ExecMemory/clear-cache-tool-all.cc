
#include "core/arch/CpuFeature.h"

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#endif

#include <assert.h>

/*
 * The compiler generates calls to __clear_cache() when creating
 * trampoline functions on the stack for use with nested functions.
 * It is expected to invalidate the instruction cache for the
 * specified range.
 */

void ClearCache(void *start, void *end) {
#if __i386__ || __x86_64__ || defined(_M_IX86) || defined(_M_X64)
/*
 * Intel processors have a unified instruction and data cache
 * so there is nothing to do
 */
#elif defined(_WIN32) && (defined(__arm__) || defined(__aarch64__))
  FlushInstructionCache(GetCurrentProcess(), start, end - start);
#elif defined(__arm__) && !defined(__APPLE__)
#if defined(__FreeBSD__) || defined(__NetBSD__)
  struct arm_sync_icache_args arg;

  arg.addr = (uintptr_t)start;
  arg.len  = (uintptr_t)end - (uintptr_t)start;

  sysarch(ARM_SYNC_ICACHE, &arg);
#elif defined(__linux__)
/*
 * We used to include asm/unistd.h for the __ARM_NR_cacheflush define, but
 * it also brought many other unused defines, as well as a dependency on
 * kernel headers to be installed.
 *
 * This value is stable at least since Linux 3.13 and should remain so for
 * compatibility reasons, warranting it's re-definition here.
 */
#define __ARM_NR_cacheflush 0x0f0002
  register int       start_reg __asm("r0")  = (int)(intptr_t)start;
  const register int end_reg __asm("r1")    = (int)(intptr_t)end;
  const register int flags __asm("r2")      = 0;
  const register int syscall_nr __asm("r7") = __ARM_NR_cacheflush;
  __asm __volatile("svc 0x0" : "=r"(start_reg) : "r"(syscall_nr), "r"(start_reg), "r"(end_reg), "r"(flags));
  assert(start_reg == 0 && "Cache flush syscall failed.");
#else
  compilerrt_abort();
#endif
#elif defined(__linux__) && defined(__mips__)
  const uintptr_t start_int = (uintptr_t)start;
  const uintptr_t end_int   = (uintptr_t)end;
#if defined(__ANDROID__) && defined(__LP64__)
  // Call synci implementation for short address range.
  const uintptr_t address_range_limit = 256;
  if ((end_int - start_int) <= address_range_limit) {
    clear_mips_cache(start, (end_int - start_int));
  } else {
    syscall(__NR_cacheflush, start, (end_int - start_int), BCACHE);
  }
#else
  syscall(__NR_cacheflush, start, (end_int - start_int), BCACHE);
#endif
#elif defined(__mips__) && defined(__OpenBSD__)
  cacheflush(start, (uintptr_t)end - (uintptr_t)start, BCACHE);
#elif defined(__aarch64__) && !defined(__APPLE__)
  uint64_t xstart = (uint64_t)(uintptr_t)start;
  uint64_t xend   = (uint64_t)(uintptr_t)end;
  uint64_t addr;

  // Get Cache Type Info
  uint64_t ctr_el0;
  __asm __volatile("mrs %0, ctr_el0" : "=r"(ctr_el0));

  /*
   * dc & ic instructions must use 64bit registers so we don't use
   * uintptr_t in case this runs in an IPL32 environment.
   */
  const int dcache_line_size = 4 << ((ctr_el0 >> 16) & 15);
  for (addr = xstart & ~(dcache_line_size - 1); addr < xend; addr += dcache_line_size)
    __asm __volatile("dc cvau, %0" ::"r"(addr));
  __asm __volatile("dsb ish");

  const int icache_line_size = 4 << ((ctr_el0 >> 0) & 15);
  for (addr = xstart & ~(icache_line_size - 1); addr < xend; addr += icache_line_size)
    __asm __volatile("ic ivau, %0" ::"r"(addr));
  __asm __volatile("isb sy");
#elif defined(__powerpc64__)
  const int line_size = 32;
  const int len       = (uintptr_t)end - (uintptr_t)start;

  const uintptr_t mask       = ~(line_size - 1);
  const uintptr_t start_line = ((uintptr_t)start) & mask;
  const uintptr_t end_line   = ((uintptr_t)start + len + line_size - 1) & mask;

  for (uintptr_t line = start_line; line < end_line; line += line_size)
    __asm__ volatile("dcbf 0, %0" : : "r"(line));
  __asm__ volatile("sync");

  for (uintptr_t line = start_line; line < end_line; line += line_size)
    __asm__ volatile("icbi 0, %0" : : "r"(line));
  __asm__ volatile("isync");
#else
#if __APPLE__
  /* On Darwin, sys_icache_invalidate() provides this functionality */
  sys_icache_invalidate(start, (uintptr_t)end - (uintptr_t)start);
#else
  compilerrt_abort();
#endif
#endif
}
