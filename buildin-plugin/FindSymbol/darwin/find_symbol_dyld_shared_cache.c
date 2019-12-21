#include <stdio.h>
#include <stdint.h>

#include <pthread.h> // pthread_once

#include <sys/mman.h> // mmap

#include <fcntl.h> // open

#include "symbol_internal.h"

#include "shared-cache/dyld_cache_format.h"

extern int __shared_region_check_np(uint64_t *startaddress);

static pthread_once_t mmap_dyld_shared_cache_once = PTHREAD_ONCE_INIT;

addr_t g_dyld_shared_cache_base_address = 0;

uint8_t *g_mmap_cache_header;
uint8_t *g_mmap_cache_local_symbol;

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

void mmap_dyld_shared_cache() {
  char cache_file_path[256] = {0};
  snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s%s", IPHONE_DYLD_SHARED_CACHE_DIR,
           DYLD_SHARED_CACHE_BASE_NAME, "arm64");
  int fd = open(cache_file_path, O_RDONLY, 0);

  uint8_t *mmap_cache_header;
  uint8_t *mmap_cache_local_symbol;

  // auto align
  mmap_cache_header = mmap(0, sizeof(struct dyld_cache_header), PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
  if (!mmap_cache_header)
    printf("mmap dyld_shared_cache header failed.\n");

  // auto align
  mmap_cache_local_symbol = mmap(0, ((struct dyld_cache_header *)mmap_cache_header)->localSymbolsSize, PROT_READ,
                                 MAP_FILE | MAP_PRIVATE, fd, ((struct dyld_cache_header *)mmap_cache_header)->localSymbolsOffset);
  if (!mmap_cache_local_symbol)
    printf("mmap dyld_shared_cache local symbol failed.\n");

  g_mmap_cache_header       = mmap_cache_header;
  g_mmap_cache_local_symbol = mmap_cache_local_symbol;
}

// refer: dyld
bool is_addr_in_dyld_shared_cache(addr_t addr, size_t length) {

  addr_t cache_base_address        = get_dyld_shared_cache_base_address();
  struct dyld_cache_header *header = cache_base_address;

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
      // readOnly = ((m->initProt & VM_PROT_WRITE) == 0);
      return true;
    }
  }
  return false;
}

uintptr_t get_dyld_shared_cache_slide() {
  addr_t cache_base_address        = get_dyld_shared_cache_base_address();
  struct dyld_cache_header *header = cache_base_address;

  const struct dyld_cache_mapping_info *mappings =
      (struct dyld_cache_mapping_info *)((char *)cache_base_address + header->mappingOffset);
  uintptr_t slide = (uintptr_t)cache_base_address - (uintptr_t)(mappings[0].address);
  return slide;
}

void get_syms_in_dyld_shared_cache(void *image_header, uintptr_t *syms, char **strs, size_t *nsyms) {

  pthread_once(&mmap_dyld_shared_cache_once, mmap_dyld_shared_cache);

  addr_t cache_base_address        = get_dyld_shared_cache_base_address();
  struct dyld_cache_header *header = cache_base_address;

  uint64_t textOffsetInCache = (uint64_t)image_header - (uint64_t)header;

  nlist_t *localNlists     = NULL;
  uint32_t localNlistCount = 0;
  const char *localStrings = NULL;

  struct dyld_cache_local_symbols_info *localInfo = (struct dyld_cache_local_symbols_info *)(g_mmap_cache_local_symbol);
  struct dyld_cache_local_symbols_entry *entries =
      (struct dyld_cache_local_symbols_entry *)(g_mmap_cache_local_symbol + localInfo->entriesOffset);
  nlist_t *allLocalNlists     = (nlist_t *)((uint8_t *)localInfo + localInfo->nlistOffset);
  const uint32_t entriesCount = localInfo->entriesCount;
  for (uint32_t i = 0; i < entriesCount; ++i) {
    if (entries[i].dylibOffset == textOffsetInCache) {
      uint32_t localNlistStart = entries[i].nlistStartIndex;
      localNlistCount          = entries[i].nlistCount;
      localNlists              = &allLocalNlists[localNlistStart];
      localStrings             = ((char *)localInfo) + localInfo->stringsOffset;
    }
  }

  *nsyms = localNlistCount;
  *syms  = localNlists;
  *strs  = localStrings;
  return;
}
