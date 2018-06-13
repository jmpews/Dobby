#include <err.h>
#include <mach-o/dyld.h>
#include <mach/task.h>
#include <stdio.h>
#include <stdlib.h>

#include "zkit.h"

#include "CommonKit/memory/common_memory_kit.h"
#include "DarwinKit/DebugKit/darwin_debug_kit.h"
#include "DarwinKit/MemoryKit/darwin_memory_kit.h"

#ifdef __LP64__
#define mach_hdr struct mach_header_64
#define sgmt_cmd struct segment_command_64
#define sect_cmd struct section_64
#define nlist_ struct nlist_64
#define LC_SGMT LC_SEGMENT_64
#define MH_MAGIC_ MH_MAGIC_64
#else
#define mach_hdr struct mach_header
#define sgmt_cmd struct segment_command
#define sect_cmd struct section
#define nlist_ struct nlist
#define LC_SGMT LC_SEGMENT
#define MH_MAGIC_ MH_MAGIC
#endif

#define load_cmd struct load_command

zz_ptr_t zz_macho_get_dyld_load_address_via_task(task_t task);

task_t zz_darwin_get_task_via_pid(int pid);

sect_cmd *zz_macho_get_section_via_name(mach_hdr *header, char *sect_name);

sgmt_cmd *zz_macho_get_segment_via_name(mach_hdr *header, char *segment_name);

zz_ptr_t zz_macho_get_section_address_via_name(mach_hdr *header, char *sect_name);

zz_ptr_t zz_macho_get_symbol_via_name(mach_hdr *header, const char *name);

load_cmd *zz_macho_get_load_command_via_cmd(mach_hdr *header, uint32_t cmd);
