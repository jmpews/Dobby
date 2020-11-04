#ifndef MachUtility_h
#define MachUtility_h

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if defined(__LP64__)
typedef struct mach_header_64     mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64         section_t;
typedef struct nlist_64           nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header     mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section         section_t;
typedef struct nlist           nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

namespace mach_kit {

struct segment_command_64 *macho_get_segment_by_name_64(struct mach_header_64 *mach_header, const char *segname);

struct section_64 *macho_get_section_by_name_64(struct mach_header_64 *mach_header, const char *segname,
                                                const char *sectname);

void *macho_get_shared_cache();

}; // namespace mach_kit

#endif
