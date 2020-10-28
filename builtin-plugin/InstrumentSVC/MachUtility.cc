#include "MachUtility.h"

#include <string.h>

#include <unistd.h>
#include <sys/syscall.h>

namespace mach_kit {

struct segment_command_64 *macho_get_segment_by_name_64(struct mach_header_64 *mach_header, const char *segname) {
  struct segment_command_64 *segment = NULL;
  struct load_command *      lc      = NULL;
  uint8_t *                  base    = (uint8_t *)mach_header;
  uint32_t                   offset  = sizeof(*mach_header);
  uint32_t                   i       = 0;

  if (mach_header->magic != MH_MAGIC_64)
    goto finish;

  for (i = 0; i < mach_header->ncmds; ++i) {
    lc = (struct load_command *)(base + offset);

    if (lc->cmd == LC_SEGMENT_64) {
      segment = (struct segment_command_64 *)lc;
      if (!strncmp(segment->segname, segname, sizeof(segment->segname))) {
        break;
      }
      segment = NULL;
    }

    offset += lc->cmdsize;
  }

finish:
  return segment;
}

struct section_64 *macho_get_section_by_name_64(struct mach_header_64 *mach_header, const char *segname,
                                                const char *sectname) {
  struct segment_command_64 *segment = NULL;
  struct section_64 *        section = NULL;
  uint32_t                   i       = 0;

  if (mach_header->magic != MH_MAGIC_64)
    goto finish;

  segment = macho_get_segment_by_name_64(mach_header, segname);
  if (!segment)
    goto finish;

  section = (struct section_64 *)(&segment[1]);
  for (i = 0; i < segment->nsects; ++i, ++section) {
    if (!strncmp(section->sectname, sectname, sizeof(section->sectname))) {
      break;
    }
  }

  if (i == segment->nsects) {
    section = NULL;
  }

finish:
  return section;
}

void *macho_get_shared_cache() {
  static void *shared_cache_load_addr = 0;
  if (shared_cache_load_addr)
    return shared_cache_load_addr;
  if (syscall(294, &shared_cache_load_addr) == 0) {
#if 0
  if (__shared_region_check_np((uint64_t *)&shared_cache_load_addr) == 0) {
#endif
    return shared_cache_load_addr;
  }
  return 0;
}

} // namespace mach_kit
