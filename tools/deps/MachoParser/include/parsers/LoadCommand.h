#ifndef parsers_loadcommand_h
#define parsers_loadcommand_h

#include <iostream>
#include <vector>

#include "../zz.h"

typedef struct _load_command_info
{
    struct load_command *load_cmd;
    zaddr fileoff;
    zpointer cmd_info;
} load_command_info_t;
typedef std::vector<load_command_info_t> load_command_infos_t;

typedef struct _section_64_info_t
{
    struct section_64 *sect_64;
    zaddr vmaddr;
    zuint32 offset;
} section_64_info_t;

typedef std::vector<section_64_info_t> section_64_infos_t;

/*
 * segment_command_64
 */
typedef struct _segment_command_64_info
{
    zaddr vmaddr;
    zuint32 fileoff;
    struct segment_command_64 *seg_cmd_64;
    section_64_infos_t sect_64_infos;
} segment_command_64_info_t;
typedef std::vector<segment_command_64_info_t> segment_command_64_infos_t;

class ZzLoadCommand
{
  public:
    load_command_infos_t load_command_infos;
    segment_command_64_infos_t segment_command_64_infos;
    section_64_infos_t section_infos;
};

#endif