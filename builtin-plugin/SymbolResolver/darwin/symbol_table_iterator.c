
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

#include "re/re.h"

void get_syms_in_single_image(mach_header_t *header, uintptr_t *nlist_array, char **string_pool,
                              uint32_t *nlist_count) {
  segment_command_t *curr_seg_cmd;
  segment_command_t *linkedit_segment   = NULL;
  segment_command_t *data_segment       = NULL;
  segment_command_t *text_segment       = NULL;
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
      char *tmp_symbol_name  = string_pool + strtab_offset;
      // TODO: what you want !!!
      if (0 && re_match(name_pattern, tmp_symbol_name) != -1) {
        return (void *)(nlist_array[i].n_value);
      }
#if 0 // DEBUG
      printf("> %s", tmp_symbol_name);
#endif
      if (1 && strcmp(name_pattern, tmp_symbol_name) == 0) {
        return (void *)(nlist_array[i].n_value);
      }
    }
  }
  return NULL;
}

void *DobbyFindSymbol(const char *image_name, const char *symbol_name_pattern) {
  void *result    = NULL;
  int image_count = _dyld_image_count();
  for (size_t i = 0; i < image_count; i++) {
    const struct mach_header *header = _dyld_get_image_header(i);
    uintptr_t slide                  = _dyld_get_image_vmaddr_slide(i);
    const char *name_                = _dyld_get_image_name(i);
    name_                            = strrchr(name_, '/') + 1;
    if (image_name != NULL && strcmp(image_name, name_))
      continue;

    uint32_t nlist_count   = 0;
    nlist_t *nlist_array = 0;
    char *string_pool    = 0;

    if (is_addr_in_dyld_shared_cache((addr_t)header, 0))
      get_syms_in_dyld_shared_cache((void *)header, (uintptr_t *)&nlist_array, &string_pool, &nlist_count);
    else
      get_syms_in_single_image((mach_header_t *)header, (uintptr_t *)&nlist_array, &string_pool, &nlist_count);

    result = iterateSymbolTable((char *)symbol_name_pattern, nlist_array, nlist_count, string_pool);
    result = (void *)((uintptr_t)result + slide);
    if (result)
      break;
  }

  struct mach_header *dyld_header = NULL;
  if (strcmp(image_name, "dyld") == 0) {
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
    result = (void *)((uintptr_t)result + (uintptr_t)dyld_header);
  }

  return result;
}
