//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef Macho_h
#define Macho_h

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <mach/mach_types.h> // task_t

#include "objc/oobjc.h"
#include "zz.h"

#define FD_INPUT 1 // read from file
#define TASK_INPUT 2 // read from remote task
#define MEM_INPUT 3 // read from self process

typedef struct
{
    int type;
    union {
        struct
        {
            pid_t pid;
            task_t task;
            zaddr baseAddr;
        } rt;
        struct
        {
            int fd;
            zpointer data;
            uint64_t length;
            zaddr baseAddr;
        } fd;
        struct
        {
            zaddr baseAddr;
        } mem;
    };
} input_t;

#include "parsers/Header.h"
#include "parsers/LoadCommand.h"
#include "parsers/ObjcRuntime.h"

#define PARSE_SIMPLE 1
#define PARSE_ALL 2

typedef struct _ZzLinkInfo
{
    zuint32 symtab_offset;
    zuint32 strtab_offset;
    zaddr symtab_rtaddr;
    zaddr strtab_rtaddr;

} ZzLinkInfo;

class Macho
{
  public:
    int parse_type;

    bool isRuntime;
    bool is64bit;
    bool isFat;
    bool isDyldLinker;

    char *dyld_path;

    input_t input;

    zaddr image_base;
    zaddr load_vmaddr;

    /* runtime var */
    zsize aslr_slide;
    zaddr linkedit_base;
    zaddr load_end_addr;
    zaddr load_addr;

    ZzHeader header;
    ZzLoadCommand loadcommands;
    ZzObjcRuntime objcruntime;
    ZzLinkInfo linkinfo;

    Macho();
    Macho(input_t input);

    virtual bool parse_macho() = 0;

    virtual void print_macho() = 0;

    bool parse_header();

    bool parse_load_command_details();

    bool parse_load_command_headers();

    bool parse_LC_SEGMENT_64(const load_command_info_t *load_cmd_info);

    bool parse_LC_SYMTAB(const load_command_info_t *load_cmd_info);

    bool parse_LC_LOAD_DYLINKER(const load_command_info_t *load_cmd_info);

    bool parse_LC_FUNCTION_STARTS(const load_command_info_t *load_cmd_info);

    bool parse_SECT();

    bool parse_SECT_CLASSLIST(const section_64_info_t *sect_info);

    bool parse_CLASS(objc_class_info_t *objc_class_info);

    bool parse_META_CLASS(objc_class_info_t *objc_class_info);

    bool parse_SUPER_CLASS(objc_class_info_t *objc_class_info);

    const section_64_info_t *get_sect_by_name(char *sectname);
    const segment_command_64_info_t *get_seg_by_name(char *segname);

    bool check_initialization();

    virtual bool macho_read(zaddr addr, zpointer data, zsize len) = 0;

    virtual char *macho_read_string(zaddr addr) = 0;
    zaddr macho_search_data(const zaddr start_addr, const zaddr end_addr,
                            const zbyte *data, const zsize len);
    bool macho_runtime_read(zaddr vmaddr, zpointer data, zsize len);

    char *macho_runtime_read_string(zaddr vmaddr);
    zaddr macho_runtime_address(zaddr vmaddr);
    zaddr macho_link_address(zaddr vmaddr);

  private:
};

objc_class_info_t *
search_class_addr(objc_class_infos_t *objc_class_infos,
                  zaddr addr);

objc_method_info_t *search_method_name(objc_method_infos_t *objc_method_infos,
                                       char *method_name);

objc_method_info_t *search_method_addr(objc_method_infos_t *objc_method_infos,
                                       zaddr method_addr);

objc_method_info_t *
hash_search_method_addr(objc_method_infos_map_t *objc_method_infos_map,
                        zaddr method_addr);

objc_method_info_t *
hash_search_method_name(objc_method_infos_strmap_t *objc_method_infos_strmap,
                        char *method_name);

zaddr macho_objc_getClass(zaddr addr);

void PrintClassInfo(objc_class_info_t *xobjc_class_info);

#endif
