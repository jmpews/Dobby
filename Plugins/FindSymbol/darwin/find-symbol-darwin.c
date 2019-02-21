
#include "z_symbol.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/vm_map.h>
#include <mach/mach.h>

#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

void *iterateSymbolTable(struct mach_header *header, const char *name);

void *ZzFindSymbol(const char *name) {
  void *result    = NULL;
  int image_count = _dyld_image_count();

  for (size_t i = 0; i < image_count; i++) {
    const struct mach_header *header = _dyld_get_image_header(i);

    result = iterateSymbolTable(header, name);
    if (result)
      break;
  }

  return result;
}

void *iterateSymbolTable(struct mach_header *header, const char *name) {
  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment   = NULL;
  segment_command_t *data_segment       = NULL;
  segment_command_t *text_segment       = NULL;
  struct symtab_command *symtab_cmd     = NULL;
  struct dysymtab_command *dysymtab_cmd = NULL;

  section_t *section;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (int i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, "__LINKEDIT") == 0) {
        linkedit_segment = cur_seg_cmd;
      } else if (strcmp(cur_seg_cmd->segname, "__DATA") == 0) {
        data_segment = cur_seg_cmd;
      } else if (strcmp(cur_seg_cmd->segname, "__TEXT") == 0) {
        text_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command *)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !linkedit_segment) {
    return NULL;
  }

  uintptr_t slide         = (uintptr_t)header - (uintptr_t)text_segment->vmaddr;
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab         = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab            = (char *)(linkedit_base + symtab_cmd->stroff);

  for (int i = 0; i < symtab_cmd->nsyms; i++) {
    uint32_t strtab_offset = symtab[i].n_un.n_strx;
    char *tmp_symbol_name  = strtab + strtab_offset;
    // TODO: what you want !!!
    if (strcmp(tmp_symbol_name, name) == 0) {
      return (void *)(symtab[i].n_value + slide);
    }
  }
  return NULL;
}