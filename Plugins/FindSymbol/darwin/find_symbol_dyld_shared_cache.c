#include <stdio.h>
#include <stdint.h>

typedef uint64_t addr_t;

addr_t g_dyld_shared_cache_base_address = 0;

addr_t get_dyld_shared_cache_base_address() {
  if (g_dyld_shared_cache_base_address)
    return g_dyld_shared_cache_base_address;
  addr_t cache_base_address = 0;
#if __i386__
  if (syscall(294, &cache_base_address) == 0) {
#else
  if (__shared_region_check_np(&cache_base_address) == 0) {
#endif
    g_dyld_shared_cache_base_address = cache_base_address;
    return get_dyld_shared_cache_base_address();
  }
  return 0;
}
