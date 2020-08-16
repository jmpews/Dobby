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

#include "common/headers/common_header.h"

#include "logging/logging.h"

static uint64_t dyld_read_uleb128(const uint8_t **p_ptr) {
  uint64_t result  = 0;
  int bit          = 0;
  const uint8_t *p = *p_ptr;
  do {
    uint64_t slice = *p & 0x7f;

    if (bit > 63) {
      FATAL("uleb128 too big for uint64");
      break;
    } else {
      result |= (slice << bit);
      bit += 7;
    }
  } while (*p++ & 0x80);
  
  *p_ptr = p;
  return result;
}

uint64_t iterate_exported_symbol(const uint8_t *exports, const char *name) {
  const char *s;
  const uint8_t *p;

  s = name;
  p = exports;
  while (p != NULL) {
    int64_t terminal_size;
    const uint8_t *children;
    uint8_t child_count, i;
    uint64_t node_offset;

    terminal_size = dyld_read_uleb128(&p);

    if (*s == '\0' && terminal_size != 0) {
      /* Skip flags. */
      dyld_read_uleb128(&p);

      /* Assume it's a plain export. */
      return dyld_read_uleb128(&p);
    }

    children    = p + terminal_size;
    child_count = *children++;
    p           = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++) {
      const char *symbol_cur;
      bool matching_edge;

      symbol_cur    = s;
      matching_edge = true;
      while (*p != '\0') {
        if (matching_edge) {
          if (*p != *symbol_cur)
            matching_edge = false;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge) {
        node_offset = dyld_read_uleb128(&p);
        s           = symbol_cur;
        break;
      } else {
        dyld_read_uleb128(&p);
      }
    }

    if (node_offset != 0)
      p = exports + node_offset;
    else
      p = NULL;
  }

  return 0;
}

void *iterate_exported_syms(mach_header_t *header, const char *symbol_name) {
  segment_command_t *curr_seg_cmd;
  struct dyld_info_command *dyld_info_cmd = NULL;
  segment_command_t *text_segment, *data_segment, *linkedit_segment;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (int i = 0; i < header->ncmds; i++, cur += curr_seg_cmd->cmdsize) {
    curr_seg_cmd = (segment_command_t *)cur;
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
  }

  if (!linkedit_segment) {
    return (void *)0;
  }

  uintptr_t slide         = (uintptr_t)header - (uintptr_t)text_segment->vmaddr;
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;

  void *exports = (void *)(linkedit_base + dyld_info_cmd->export_off);
  if (exports == NULL)
    return (void *)0;

  void *off = iterate_exported_symbol(exports, symbol_name);
  return off;
}

void get_syms_in_single_image(mach_header_t *header, uintptr_t *nlist_array, char **string_pool,
                              uint32_t *nlist_count) {
  segment_command_t *curr_seg_cmd;
  segment_command_t *text_segment, *data_segment, *linkedit_segment;
  struct symtab_command *symtab_cmd     = NULL;
  struct dysymtab_command *dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (int i = 0; i < header->ncmds; i++, cur += curr_seg_cmd->cmdsize) {
    curr_seg_cmd = (segment_command_t *)cur;
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
    
    result = iterate_exported_syms((mach_header_t *) header, symbol_name_pattern);
    if (result) {
      result = (void *)((uintptr_t)result + slide);
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

#if 1
__attribute__((constructor)) static void ctor() {
  const struct mach_header *header = NULL;
  header                           = _dyld_get_image_header(0);
  
  void *addr = iterate_exported_syms(header, "_main");
  LOG("export %p", addr);

}
#endif
