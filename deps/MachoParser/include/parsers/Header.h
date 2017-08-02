#ifndef parsers_header_h
#define parsers_header_h

/*
    Better Design???
    split whole parser into several modules
*/

#include <mach/mach_types.h>

#include <iostream>
#include <vector>

class Macho;

typedef struct fat_arch_info {
    struct fat_arch *arch;
    Macho *macho;
} fat_arch_info_t;

typedef std::vector<fat_arch_info_t> fat_arch_infos_t;

class ZZHeader {
public:
    bool isFat;
    bool is64bit;

    struct mach_header *header;
    struct mach_header_64 *header64;

    struct fat_header *fat_header;
    fat_arch_infos_t fat_arch_infos;
};

#endif