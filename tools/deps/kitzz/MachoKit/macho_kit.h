#include <err.h>
#include <mach-o/dyld.h>
#include <mach/task.h>
#include <stdio.h>
#include <stdlib.h>

#include "kitzz.h"

#include "CommonKit/memory/common_memory_kit.h"
#include "DarwinKit/DebugKit/darwin_debug_kit.h"
#include "DarwinKit/MemoryKit/darwin_memory_kit.h"

zz_ptr_t zz_macho_get_dyld_load_address_via_task(task_t task);

task_t zz_darwin_get_task_via_pid(int pid);

struct section_64 *zz_macho_get_section_64_via_name(struct mach_header_64 *header, char *sect_name);

struct segment_command_64 *zz_macho_get_segment_64_via_name(struct mach_header_64 *header, char *segment_name);

zz_ptr_t zz_macho_get_section_64_address_via_name(struct mach_header_64 *header, char *sect_name);

zz_ptr_t zz_macho_get_symbol_via_name(struct mach_header_64 *header, const char *name);

struct load_command *zz_macho_get_load_command_via_cmd(struct mach_header_64 *header, uint32_t cmd);
