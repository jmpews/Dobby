#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>  // pthread_once
#include <sys/mman.h> // mmap
#include <fcntl.h>    // open
#include <sys/stat.h>

#include "SymbolResolver/macho/shared_cache_internal.h"
#include "SymbolResolver/macho/shared-cache/dyld_cache_format.h"

#include "logging/logging.h"

#include <string>

#undef LOG_TAG
#define LOG_TAG "DobbySymbolResolverCache"

#if 0
extern "C" {
int __shared_region_check_np(uint64_t *startaddress);
}
#endif

extern "C" {
extern const char *dyld_shared_cache_file_path();
extern int __shared_region_check_np(uint64_t *startaddress);
}

static char *fast_get_shared_cache_path() {
#if defined(_M_IX86) || defined(__i386__) || defined(_M_X64) || defined(__x86_64__)
  return NULL;
#endif

  const char *path = NULL;
  do {
    path = dyld_shared_cache_file_path();
    if (path != NULL) {
      break;
    } else {
      struct stat statbuf;
      int r = 0;

      path = IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64";
      r = stat(path, &statbuf);
      if (r == 0) {
        break;
      }
      path = IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64e";
      r = stat(path, &statbuf);
      if (r == 0) {
        break;
      }
      path = MACOSX_MRM_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64";
      r = stat(path, &statbuf);
      if (r == 0) {
        break;
      }
      path = MACOSX_MRM_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64e";
      r = stat(path, &statbuf);
      if (r == 0) {
        break;
      }
    }
  } while (0);

  if (path != NULL) {
    return strdup(path);
  }

  return NULL;
}

#include <mach/mach.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
struct dyld_cache_header *shared_cache_get_load_addr() {
  static struct dyld_cache_header *shared_cache_load_addr = 0;

  // task info
  task_dyld_info_data_t task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count)) {
    return NULL;
  }

  // get dyld load address
  const struct dyld_all_image_infos *infos =
      (struct dyld_all_image_infos *)(uintptr_t)task_dyld_info.all_image_info_addr;
  shared_cache_load_addr = (struct dyld_cache_header *)infos->sharedCacheBaseAddress;

  return shared_cache_load_addr;

#if 0
  if (shared_cache_load_addr)
    return shared_cache_load_addr;
#if 0
  if (syscall(294, &shared_cache_load_addr) == 0) {
#else
  if (__shared_region_check_np((uint64_t *)&shared_cache_load_addr) != 0) {
#endif
  shared_cache_load_addr = 0;
}
#endif
  return shared_cache_load_addr;
}

int load_shared_cache_symbols(shared_cache_ctx_t *ctx) {
  std::string path = dyld_shared_cache_file_path();
  path += ".symbols";

  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    LOG(1, "open %s failed", path.c_str());
    return -1;
  }

  struct stat statbuf;
  stat(path.c_str(), &statbuf);
  auto file_size = statbuf.st_size;

  auto mmap_shared_cache = (struct dyld_cache_header *)mmap(0, file_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
  if (mmap_shared_cache == MAP_FAILED) {
    LOG(1, "mmap %s failed", path.c_str());
    return -1;
  }

  ctx->mmap_shared_cache = mmap_shared_cache;
  return 0;
}

int shared_cache_ctx_init(shared_cache_ctx_t *ctx) {
  load_shared_cache_symbols(ctx);

  auto runtime_shared_cache = shared_cache_get_load_addr();
  if (runtime_shared_cache == NULL) {
    return KERN_FAILURE;
  }
  ctx->runtime_shared_cache = runtime_shared_cache;

  // shared cache slide
  const struct dyld_cache_mapping_info *mappings =
      (struct dyld_cache_mapping_info *)((char *)runtime_shared_cache + runtime_shared_cache->mappingOffset);
  uintptr_t slide = (uintptr_t)runtime_shared_cache - (uintptr_t)(mappings[0].address);
  ctx->runtime_slide = slide;

  {
    auto mmap_shared_cache = ctx->mmap_shared_cache;

    auto localInfo =
        (struct dyld_cache_local_symbols_info *)((char *)mmap_shared_cache + mmap_shared_cache->localSymbolsOffset);

    auto localEntries = (struct dyld_cache_local_symbols_entry_64 *)((char *)localInfo + localInfo->entriesOffset);

    ctx->local_symbols_info = localInfo;
    ctx->local_symbols_entries = localEntries;

    ctx->symtab = (nlist_t *)((char *)localInfo + localInfo->nlistOffset);
    ctx->strtab = ((char *)localInfo) + localInfo->stringsOffset;
  }
  return 0;
}

// refer: dyld
bool shared_cache_is_contain(shared_cache_ctx_t *ctx, addr_t addr, size_t length) {
  struct dyld_cache_header *runtime_shared_cache;
  if (ctx) {
    runtime_shared_cache = ctx->runtime_shared_cache;
  } else {
    runtime_shared_cache = shared_cache_get_load_addr();
  }

  addr_t region_start = runtime_shared_cache->sharedRegionStart + ctx->runtime_slide;
  addr_t region_end = region_start + runtime_shared_cache->sharedRegionSize;
  if (addr >= region_start && addr < region_end)
    return true;

  return false;
}

int shared_cache_get_symbol_table(shared_cache_ctx_t *ctx, mach_header_t *image_header, nlist_t **out_symtab,
                                  uint32_t *out_symtab_count, char **out_strtab) {
  uint64_t textOffsetInCache = (uint64_t)image_header - (uint64_t)ctx->runtime_shared_cache;

  nlist_t *localNlists = NULL;
  uint32_t localNlistCount = 0;
  const char *localStrings = NULL;

  const uint32_t entriesCount = ctx->local_symbols_info->entriesCount;
  for (uint32_t i = 0; i < entriesCount; ++i) {
    if (ctx->local_symbols_entries[i].dylibOffset == textOffsetInCache) {
      uint32_t localNlistStart = ctx->local_symbols_entries[i].nlistStartIndex;
      localNlistCount = ctx->local_symbols_entries[i].nlistCount;
      localNlists = &ctx->symtab[localNlistStart];

#if 0
      static struct dyld_cache_image_info *imageInfos = NULL;
      imageInfos = (struct dyld_cache_image_info *)((addr_t)g_mmap_shared_cache + g_mmap_shared_cache->imagesOffset);
      char *image_name = (char *)g_mmap_shared_cache + imageInfos[i].pathFileOffset;
      LOG(1, "dyld image: %s", image_name);
#endif
    }
  }
  *out_symtab = localNlists;
  *out_symtab_count = (uint32_t)localNlistCount;
  *out_strtab = (char *)ctx->strtab;
  return 0;
}
