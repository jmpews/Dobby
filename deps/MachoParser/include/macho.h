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

#ifndef macho_h
#define macho_h

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <mach/mach_types.h> // task
#include <sys/types.h>       // pid_t

#include "objc/oobjc.h"
#include "zz.h"

/*
    for system type: like `struct load_command`, `stuct segment_command_64`
 */

/*
 * load command
 *
 */

// typedef struct _load_command_info {
//    struct load_command *load_cmd;
//    zaddr cmd_addr;
//    zpointer cmd_info;
//} load_command_info_t;
// typedef std::vector<load_command_info_t> load_command_infos_t;
//
// typedef std::vector<struct section_64 *> section_64_infos_t;
//
///*
// * segment_command_64
// */
// typedef struct _segment_command_64_info {
//    struct segment_command_64 *seg_cmd_64;
//    section_64_infos_t sect_64_infos;
//} segment_command_64_info_t;
// typedef std::vector<segment_command_64_info_t *> segment_command_64_infos_t;

/*
 * objc method
 */
struct _objc_method_info;
typedef std::vector<_objc_method_info *> objc_method_infos_t;
typedef struct _objc_class_info {
    struct objc::objc_class *objc_class;
    zaddr class_addr;
    char *class_name;
    struct _objc_class_info *meta_class_info;
    struct _objc_class_info *super_class_info;
    objc_method_infos_t objc_method_infos;
} objc_class_info_t;
typedef std::vector<objc_class_info_t *> objc_class_infos_t;

/*
 * objc method
 */
// TODO: do need map?
typedef struct _objc_method_info {
    struct objc::method_t *objc_method;
    zaddr method_addr;
    char *method_name;
    objc_class_info_t *objc_class_info;
} objc_method_info_t;

typedef std::unordered_map<zaddr, objc_method_info_t *> objc_method_infos_map_t;
typedef std::unordered_map<std::string, objc_method_info_t *>
        objc_method_infos_strmap_t;

#define FD_INPUT 1   // read from file
#define TASK_INPUT 2 // read from remote task
#define MEM_INPUT 3  // read from self process

typedef struct {
    int type;
    union {
        struct {
            pid_t pid;
            task_t task;
            zaddr baseAddr;
        } rt;
        struct {
            int fd;
            zpointer data;
            uint64_t length;
            zaddr baseAddr;
        } fd;
        struct {
            zaddr baseAddr;
        } mem;
    };
} input_t;

#define CLASS_FUNC 2
#define DEFAULT_FUNC 1

typedef struct {
    zaddr func_addr;
    int func_type;
    objc_method_info_t *class_method;
} func_info_t;
typedef std::vector<func_info_t *> funcs_t;

#include "parsers/Header.h"
#include "parsers/LoadCommand.h"

#define PARSE_SIMPLE 1
#define PARSE_ALL 2

class Macho {
public:
    int parse_type;
    bool m_isLog;

    bool m_is64bit;
    bool m_isDyldLinker;
    char *m_dyld_path;
    bool m_isFat;

    input_t m_input;

    ZZHeader header;
    ZZLoadCommand loadcommands;

    /* macho standard var */
    zaddr m_vmaddr_64;
    zaddr m_symtab_addr;
    zaddr m_strtab_addr;

    objc_class_infos_t m_objc_class_infos;
    objc_method_infos_t m_objc_method_infos;
    objc_method_infos_map_t m_objc_method_infos_map;
    objc_method_infos_strmap_t m_objc_method_infos_strmap;
    funcs_t m_funcs;

    /* runtime var */
    size_t m_aslr_slide;
    zaddr m_link_edit_base;
    zaddr m_load_end_addr;
    zaddr m_load_addr;

    Macho();

    Macho(input_t input);

    bool parse_macho();

    void print_macho();

    bool parse_universal();

    Macho *parse_macho_arch(int arch);

    bool parse_header();

    bool parse_load_command_details();

    bool parse_load_command_headers();

    bool parse_LC_SEGMENT_64(const load_command_info_t *load_cmd_info);

    bool parse_LC_SYMTAB(const load_command_info_t *load_cmd_info);

    bool parse_LC_LOAD_DYLINKER(const load_command_info_t *load_cmd_info);

    bool parse_LC_FUNCTION_STARTS(const load_command_info_t *load_cmd_info);

    bool parse_section();

    const section_64_info_t *get_sect_by_name(char *sectname);

    bool parse_SECT_CLASSLIST(const section_64_info_t *sect_info);

    bool parse_CLASS(objc_class_info_t *objc_class_info);

    bool parse_META_CLASS(objc_class_info_t *objc_class_info);

    bool parse_SUPER_CLASS(objc_class_info_t *objc_class_info);

    objc_class_info_t *parse_OBJECT(zaddr addr);

    bool object_isClass(zaddr object_addr);

    zaddr object_getClass(zaddr object_addr);

    bool is_self_memory(zaddr addr);

    bool checkInitialization();

    bool macho_read(zaddr addr, zpointer data, zsize len);

    zaddr macho_search_data(const zaddr start_addr, const zaddr end_addr,
                            const zbyte *data, const zsize len);

    char *macho_read_string_fake_aslr(zaddr addr);

    bool macho_read_fake_aslr(zaddr addr, zpointer data, zsize len);

    char *macho_read_string(zaddr addr);

private:
};

objc_class_info_t *search_class_addr(objc_class_infos_t *objc_class_infos,
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
