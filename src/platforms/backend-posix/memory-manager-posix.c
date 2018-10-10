#include "memory-helper-posix.h"
#include "memory_manager.h"

#if !defined(__APPLE__) || USE_POSIX_IN_DARWIN

PLATFORM_API int memory_manager_cclass(get_page_size)() {
  int page_size;
  page_size = posix_memory_helper_cclass(get_page_size)();
  return page_size;
}

PLATFORM_API void memory_manager_cclass(patch_code)(memory_manager_t *self, void *dest, void *src, int count) {
  posix_memory_helper_cclass(patch_code)(dest, src, count);
  return;
}

PLATFORM_API void *memory_manager_cclass(allocate_page)(memory_manager_t *self, int prot, int n) {
  return posix_memory_helper_cclass(allocate_page)(prot, n);
}

PLATFORM_API void memory_manager_cclass(set_page_permission)(void *page_address, int prot, int n) {
  posix_memory_helper_cclass(set_page_permission)(page_address, prot, n);
}

#endif