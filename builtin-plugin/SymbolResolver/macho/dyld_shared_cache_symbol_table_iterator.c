#include <stdio.h>
#include <stdint.h>

#include <pthread.h> // pthread_once

#include <sys/mman.h> // mmap

#include <fcntl.h> // open

#include "shared_cache_internal.h"

#include "shared-cache/dyld_cache_format.h"

#include "logging/logging.h"

extern int __shared_region_check_np(uint64_t *startaddress);

static pthread_once_t mmap_dyld_shared_cache_once = PTHREAD_ONCE_INIT;

struct dyld_cache_header *g_mmap_shared_cache_header;
struct dyld_cache_header *g_mmap_shared_cache;

int g_dyld_shared_cache_fd = 0;

void *get_shared_cache_load_addr() {
  static void *shared_cache_load_addr = 0;
  if (shared_cache_load_addr)
    return shared_cache_load_addr;
#if __i386__
  if (syscall(294, &shared_cache_load_addr) == 0) {
#else
  if (__shared_region_check_np((uint64_t *)&shared_cache_load_addr) == 0) {
#endif
    return shared_cache_load_addr;
  }
  return 0;
}

void mmap_dyld_shared_cache() {
  char cache_file_path[1024] = {0};
  snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s%s", IPHONE_DYLD_SHARED_CACHE_DIR,
           DYLD_SHARED_CACHE_BASE_NAME, "arm64");
  int fd = open(cache_file_path, O_RDONLY, 0);
  if (fd == -1) {
    snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s%s", IPHONE_DYLD_SHARED_CACHE_DIR,
             DYLD_SHARED_CACHE_BASE_NAME, "arm64e");
    fd = open(cache_file_path, O_RDONLY, 0);
  }
  if (fd == -1) {
    FATAL("open %s failed", cache_file_path);
  }

  struct dyld_cache_header *mmap_shared_cache_header;
  struct dyld_cache_header *mmap_shared_cache;

  // auto align
  mmap_shared_cache_header = get_shared_cache_load_addr();

  mmap_shared_cache = mmap(0, mmap_shared_cache_header->localSymbolsOffset + mmap_shared_cache_header->localSymbolsSize,
                           PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
  
  if(mmap_shared_cache == MAP_FAILED)
    FATAL("mmap shared cache failed");
  
#ifndef DOBBY_DEBUG
  // remove unused memory
  // munmap(mmap_shared_cache, mmap_shared_cache_header->localSymbolsOffset);
#endif

  g_mmap_shared_cache_header = mmap_shared_cache_header;
  g_mmap_shared_cache        = mmap_shared_cache;
}

// refer: dyld
bool is_addr_in_dyld_shared_cache(addr_t addr, size_t length) {
  addr_t cache_base_address        = (addr_t)get_shared_cache_load_addr();
  struct dyld_cache_header *header = (struct dyld_cache_header *)cache_base_address;

  const struct dyld_cache_mapping_info *mappings =
      (struct dyld_cache_mapping_info *)((char *)cache_base_address + header->mappingOffset);
  uintptr_t slide       = (uintptr_t)cache_base_address - (uintptr_t)(mappings[0].address);
  uintptr_t unslidStart = (uintptr_t)addr - slide;

  // quick out if after end of cache
  if (unslidStart > (mappings[2].address + mappings[2].size))
    return false;

  // walk cache regions
  const struct dyld_cache_mapping_info *mappingsEnd = &mappings[header->mappingCount];
  uintptr_t unslidEnd                               = unslidStart + length;
  for (const struct dyld_cache_mapping_info *m = mappings; m < mappingsEnd; ++m) {
    if ((unslidStart >= m->address) && (unslidEnd < (m->address + m->size))) {
      return true;
    }
  }
  return false;
}

void get_syms_in_dyld_shared_cache(void *image_header, uintptr_t *nlist_array_ptr, char **string_pool_ptr,
                                   uint32_t *nlist_count_ptr) {
  pthread_once(&mmap_dyld_shared_cache_once, mmap_dyld_shared_cache);

  addr_t cache_base_address        = get_shared_cache_load_addr();
  struct dyld_cache_header *header = (struct dyld_cache_header *)cache_base_address;

  uint64_t textOffsetInCache = (uint64_t)image_header - (uint64_t)header;

  nlist_t *localNlists     = NULL;
  uint32_t localNlistCount = 0;
  const char *localStrings = NULL;

  static struct dyld_cache_local_symbols_info *localsInfo = NULL;
  localsInfo =
      (struct dyld_cache_local_symbols_info *)((addr_t)g_mmap_shared_cache + g_mmap_shared_cache->localSymbolsOffset);

  static struct dyld_cache_local_symbols_entry *entries = NULL;
  entries = (struct dyld_cache_local_symbols_entry *)((char *)localsInfo + localsInfo->entriesOffset);

  localNlists                 = (nlist_t *)((uint8_t *)localsInfo + localsInfo->nlistOffset);
  localStrings                = ((char *)localsInfo) + localsInfo->stringsOffset;
  const uint32_t entriesCount = localsInfo->entriesCount;
  for (uint32_t i = 0; i < entriesCount; ++i) {
    if (entries[i].dylibOffset == textOffsetInCache) {
      uint32_t localNlistStart = entries[i].nlistStartIndex;
      localNlistCount          = entries[i].nlistCount;
      localNlists              = &localNlists[localNlistStart];
      
#if defined(DOBBY_DEBUG)
      static struct dyld_cache_image_info *imageInfos = NULL;
      imageInfos = (struct dyld_cache_image_info *)((addr_t)g_mmap_shared_cache + g_mmap_shared_cache->imagesOffset);
      char *image_name = (char *)g_mmap_shared_cache + imageInfos[i].pathFileOffset;
      DLOG("dyld image: %s", image_name);
#endif
    }
  }

  *nlist_count_ptr = (uint32_t)localNlistCount;
  *nlist_array_ptr = (uintptr_t)localNlists;
  *string_pool_ptr = (char *)localStrings;
  return;
}
