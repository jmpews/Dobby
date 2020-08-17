#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/vm_map.h>
#include <mach/mach.h>

#include <string.h>

#include "shared_cache_internal.h"

#include "dobby_symbol_resolver.h"
#include "common/headers/common_header.h"

#include "logging/logging.h"

#define LOG_TAG "DobbySymbolResolver"

static uint64_t dyld_read_uleb128(const uint8_t **p_ptr, const uint8_t *end) {
  uint64_t result  = 0;
  int bit          = 0;
  const uint8_t *p = *p_ptr;
  do {
    if (p == end) {
      // diag.error("malformed uleb128");
      break;
    }
    uint64_t slice = *p & 0x7f;

    if (bit > 63) {
      // diag.error("uleb128 too big for uint64");
      break;
    } else {
      result |= (slice << bit);
      bit += 7;
    }
  } while (*p++ & 0x80);

  *p_ptr = p;
  return result;
}

// dyld
// bool MachOLoaded::findExportedSymbol
 void *walk_exported_trie(const uint8_t *start, const uint8_t *end, const char *symbol) {
  uint32_t visitedNodeOffsets[128];
  int visitedNodeOffsetCount                   = 0;
  visitedNodeOffsets[visitedNodeOffsetCount++] = 0;
  const uint8_t *p                             = start;
  while (p < end) {
    uint64_t terminalSize = *p++;
    if (terminalSize > 127) {
      // except for re-export-with-rename, all terminal sizes fit in one byte
      --p;
      terminalSize = dyld_read_uleb128(&p, end);
    }
    if ((*symbol == '\0') && (terminalSize != 0)) {
      // skip flag == EXPORT_SYMBOL_FLAGS_REEXPORT
      dyld_read_uleb128(&p, end);
      return (void *)dyld_read_uleb128(&p, end);
    }
    const uint8_t *children = p + terminalSize;
    if (children > end) {
      //diag.error("malformed trie node, terminalSize=0x%llX extends past end of trie\n", terminalSize);
      return NULL;
    }
    uint8_t childrenRemaining = *children++;
    p                         = children;
    uint64_t nodeOffset       = 0;
    for (; childrenRemaining > 0; --childrenRemaining) {
      const char *ss = symbol;
      bool wrongEdge = false;
      // scan whole edge to get to next edge
      // if edge is longer than target symbol name, don't read past end of symbol name
      char c = *p;
      while (c != '\0') {
        if (!wrongEdge) {
          if (c != *ss)
            wrongEdge = true;
          ++ss;
        }
        ++p;
        c = *p;
      }
      if (wrongEdge) {
        // advance to next child
        ++p; // skip over zero terminator
        // skip over uleb128 until last byte is found
        while ((*p & 0x80) != 0)
          ++p;
        ++p; // skip over last byte of uleb128
        if (p > end) {
          // diag.error("malformed trie node, child node extends past end of trie\n");
          return NULL;
        }
      } else {
        // the symbol so far matches this edge (child)
        // so advance to the child's node
        ++p;
        nodeOffset = dyld_read_uleb128(&p, end);
        if ((nodeOffset == 0) || (&start[nodeOffset] > end)) {
          // diag.error("malformed trie child, nodeOffset=0x%llX out of range\n", nodeOffset);
          return NULL;
        }
        symbol = ss;
        break;
      }
    }
    if (nodeOffset != 0) {
      if (nodeOffset > (uint64_t)(end - start)) {
        // diag.error("malformed trie child, nodeOffset=0x%llX out of range\n", nodeOffset);
        return NULL;
      }
      for (int i = 0; i < visitedNodeOffsetCount; ++i) {
        if (visitedNodeOffsets[i] == nodeOffset) {
          // diag.error("malformed trie child, cycle to nodeOffset=0x%llX\n", nodeOffset);
          return NULL;
        }
      }
      visitedNodeOffsets[visitedNodeOffsetCount++] = (uint32_t)nodeOffset;
      if (visitedNodeOffsetCount >= 128) {
        // diag.error("malformed trie too deep\n");
        return NULL;
      }
      p = &start[nodeOffset];
    } else
      p = end;
  }
  return NULL;
}

void *iterate_exported_symbol(mach_header_t *header, const char *symbol_name) {
  segment_command_t *curr_seg_cmd;
  struct dyld_info_command *dyld_info_cmd = NULL;
  segment_command_t *text_segment, *data_segment, *linkedit_segment;

  curr_seg_cmd = (segment_command_t *)((addr_t)header + sizeof(mach_header_t));
  for (int i = 0; i < header->ncmds; i++) {
    switch (curr_seg_cmd->cmd) {
    case LC_SEGMENT_ARCH_DEPENDENT: {
      if (strcmp(curr_seg_cmd->segname, "__LINKEDIT") == 0) {
        linkedit_segment = curr_seg_cmd;
      } else if (strcmp(curr_seg_cmd->segname, "__TEXT") == 0) {
        text_segment = curr_seg_cmd;
      }
    } break;
    case LC_DYLD_INFO:
    case LC_DYLD_INFO_ONLY: {
      dyld_info_cmd = (typeof(dyld_info_cmd))curr_seg_cmd;
    } break;
    default:
      break;
    };
    curr_seg_cmd = (segment_command_t *)((addr_t)curr_seg_cmd + curr_seg_cmd->cmdsize);
  }

  if (!linkedit_segment) {
    return (void *)0;
  }

  uintptr_t slide         = (uintptr_t)header - (uintptr_t)text_segment->vmaddr;
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;

  void *exports = (void *)(linkedit_base + dyld_info_cmd->export_off);
  if (exports == NULL)
    return (void *)0;

  void *off = (void *)walk_exported_trie((const uint8_t *)exports,
                                         (const uint8_t *)exports + dyld_info_cmd->export_size, symbol_name);
  if (off == (void *)0) {
    if (symbol_name[0] != '_' && strlen(&symbol_name[1]) >= 1) {
      char _symbol_name[1024] = {0};
      _symbol_name[0]         = '_';
      strcpy(&_symbol_name[1], symbol_name);
      off = (void *)walk_exported_trie((const uint8_t *)exports, (const uint8_t *)exports + dyld_info_cmd->export_size,
                                       _symbol_name);
    }
  }
  return off;
}

void get_syms_in_single_image(mach_header_t *header, uintptr_t *nlist_array, char **string_pool,
                              uint32_t *nlist_count) {
  segment_command_t *curr_seg_cmd;
  segment_command_t *text_segment, *data_segment, *linkedit_segment;
  struct symtab_command *symtab_cmd     = NULL;
  struct dysymtab_command *dysymtab_cmd = NULL;

  curr_seg_cmd = (segment_command_t *)((addr_t)header + sizeof(mach_header_t));
  for (int i = 0; i < header->ncmds; i++) {
    if (curr_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(curr_seg_cmd->segname, "__LINKEDIT") == 0) {
        linkedit_segment = curr_seg_cmd;
      } else if (strcmp(curr_seg_cmd->segname, "__DATA") == 0) {
        data_segment = curr_seg_cmd;
      } else if (strcmp(curr_seg_cmd->segname, "__TEXT") == 0) {
        text_segment = curr_seg_cmd;
      }
    } else if (curr_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command *)curr_seg_cmd;
    } else if (curr_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command *)curr_seg_cmd;
    }
    curr_seg_cmd = (segment_command_t *)((addr_t)curr_seg_cmd + curr_seg_cmd->cmdsize);
  }

  if (!symtab_cmd || !linkedit_segment) {
    return;
  }

  uintptr_t slide         = (uintptr_t)header - (uintptr_t)text_segment->vmaddr;
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab         = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab            = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t symtab_count   = symtab_cmd->nsyms;

  *nlist_count = symtab_count;
  *nlist_array = (uintptr_t)symtab;
  *string_pool = (char *)strtab;
}

void *iterateSymbolTable(char *name_pattern, nlist_t *nlist_array, uint32_t nlist_count, char *string_pool) {
  for (uint32_t i = 0; i < nlist_count; i++) {
    if (nlist_array[i].n_value) {
      uint32_t strtab_offset = nlist_array[i].n_un.n_strx;
      char *symbol_name      = string_pool + strtab_offset;
#if 0
      LOG("> %s", symbol_name);
#endif
      if (strcmp(name_pattern, symbol_name) == 0) {
        return (void *)(nlist_array[i].n_value);
      }
      if (symbol_name[0] == '_') {
        if (strcmp(name_pattern, &symbol_name[1]) == 0) {
          return (void *)(nlist_array[i].n_value);
        }
      }
    }
  }
  return NULL;
}

PUBLIC void *DobbySymbolResolver(const char *image_name, const char *symbol_name_pattern) {
  void *result    = NULL;
  int image_count = _dyld_image_count();
  for (size_t i = 0; i < image_count; i++) {
    const struct mach_header *header = NULL;
    header                           = _dyld_get_image_header(i);
    uintptr_t slide                  = 0;
    slide                            = _dyld_get_image_vmaddr_slide(i);
    const char *path                 = NULL;
    path                             = _dyld_get_image_name(i);

    if (image_name != NULL && strstr(path, image_name) == NULL)
      continue;

    DLOG("resolve image: %s", path);

    uint32_t nlist_count = 0;
    nlist_t *nlist_array = 0;
    char *string_pool    = 0;

    if (is_addr_in_dyld_shared_cache((addr_t)header, 0))
      get_syms_in_dyld_shared_cache((void *)header, (uintptr_t *)&nlist_array, &string_pool, &nlist_count);
    result = iterateSymbolTable((char *)symbol_name_pattern, nlist_array, nlist_count, string_pool);
    if (result) {
      result = (void *)((uintptr_t)result + slide);
      break;
    }

    get_syms_in_single_image((mach_header_t *)header, (uintptr_t *)&nlist_array, &string_pool, &nlist_count);
    result = iterateSymbolTable((char *)symbol_name_pattern, nlist_array, nlist_count, string_pool);
    if (result) {
      result = (void *)((uintptr_t)result + slide);
      break;
    }

    result = iterate_exported_symbol((mach_header_t *)header, symbol_name_pattern);
    if (result) {
      result = (void *)((uintptr_t)result + (uintptr_t)header);
      break;
    }
  }

  struct mach_header *dyld_header = NULL;
  if (image_name != NULL && strcmp(image_name, "dyld") == 0) {
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count)) {
      return NULL;
    }

    const struct dyld_all_image_infos *infos =
        (struct dyld_all_image_infos *)(uintptr_t)task_dyld_info.all_image_info_addr;
    dyld_header = (struct mach_header *)infos->dyldImageLoadAddress;

    uint32_t nlist_count = 0;
    nlist_t *nlist_array = 0;
    char *string_pool    = 0;
    get_syms_in_single_image((mach_header_t *)dyld_header, (uintptr_t *)&nlist_array, &string_pool, &nlist_count);

    result = iterateSymbolTable((char *)symbol_name_pattern, nlist_array, nlist_count, string_pool);
    if (result)
      result = (void *)((uintptr_t)result + (uintptr_t)dyld_header);
  }

  return result;
}

#if defined(DOBBY_DEBUG) && 1
__attribute__((constructor)) static void ctor() {
  mach_header_t *header = NULL;
  header                = (mach_header_t *)_dyld_get_image_header(0);
  
  void *addr = (void *)((addr_t)iterate_exported_symbol(header, "_mainxx") + (addr_t)header);
  LOG("export %p", addr);
}
#endif
