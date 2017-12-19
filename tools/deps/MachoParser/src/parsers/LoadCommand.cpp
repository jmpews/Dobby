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

#include <assert.h>

// #include <objc/runtime.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <pthread.h>

#include "zz.h"
#include "Macho.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "../zzdeps/common/LEB128.h"
#include "../zzdeps/common/debugbreak.h"
#include "../zzdeps/darwin/memory-utils-darwin.h"
#ifdef __cplusplus
}
#endif

const segment_command_64_info_t *Macho::get_seg_by_name(char *segname)
{
    for (const auto &seg : this->loadcommands.segment_command_64_infos)
    {
        /* iterate dump section */
        if (!strcmp(seg.seg_cmd_64->segname, segname))
        {
            return &seg;
        }
    }
    return NULL;
}

bool Macho::parse_load_command_headers()
{
    zsize ncmds = 0;
    zaddr tmp_addr;
    zpointer cmd_info;

    if (this->is64bit)
    {
        ncmds = header.header64->ncmds;
        tmp_addr = sizeof(struct mach_header_64);
    }
    else
    {
        Serror("only support x86_64.");
        return FALSE;
    }

    struct load_command *load_cmd;

    for (int i = 0; i < ncmds; i++)
    {
        load_command_info_t load_cmd_info;
        load_cmd = (struct load_command *)malloc(sizeof(struct load_command));
        macho_runtime_read(tmp_addr, load_cmd, sizeof(struct load_command));

        switch (load_cmd->cmd)
        {
        case LC_SEGMENT_64:
            /* struct segment_command_64 *seg_cmd_64; */
            cmd_info = (struct segment_command_64 *)malloc(
                sizeof(struct segment_command_64));
            macho_runtime_read(tmp_addr, cmd_info, sizeof(struct segment_command_64));
            break;
        case LC_ID_DYLINKER:
            this->isDyldLinker = TRUE;
            break;
        case LC_SYMTAB:
            /* struct symtab_command *sym_cmd; */
            cmd_info = (struct symtab_command *)malloc(sizeof(struct symtab_command));
            macho_runtime_read(tmp_addr, cmd_info, sizeof(struct symtab_command));
            break;
        case LC_FUNCTION_STARTS:
            /* struct linkedit_data_command *funcstart_cmd; */
            cmd_info = (struct linkedit_data_command *)malloc(
                sizeof(struct linkedit_data_command));
            macho_runtime_read(tmp_addr, cmd_info, sizeof(struct linkedit_data_command));
            break;
        case LC_LOAD_DYLINKER:
            /* struct dylinker_command *dy_cmd; */
            cmd_info =
                (struct dylinker_command *)malloc(sizeof(struct dylinker_command));
            macho_runtime_read(tmp_addr, cmd_info, sizeof(struct dylinker_command));
            break;
        default:
            cmd_info = (struct load_command *)malloc(load_cmd->cmdsize);
            macho_runtime_read(tmp_addr, cmd_info, load_cmd->cmdsize);
            break;
        }

        load_cmd_info.cmd_info = cmd_info;
        load_cmd_info.load_cmd = load_cmd;
        load_cmd_info.fileoff = tmp_addr;

        this->loadcommands.load_command_infos.push_back(load_cmd_info);

        /* move to next load_command */
        tmp_addr += load_cmd->cmdsize;
    }
    return TRUE;
}

/*
 * `tp` is equal to `temp`
 */
bool Macho::parse_load_command_details()
{
    Sdebug("start dump LOAD_COMMANDS...");

    /* old style */

    //    load_command_infos_t *tmp_load_command_infos;
    //
    //    tmp_load_command_infos = &this->loadcommands.load_command_infos;
    //
    //
    //    /* iterate the load commands */
    //    std::vector<load_command_info_t>::iterator iter;
    //    load_command_info_t *tmp_load_cmd_info;
    //    for (iter = tmp_load_command_infos->begin(); iter !=
    //    tmp_load_command_infos->end(); iter++) {
    //        tmp_load_cmd_info = &(*iter);
    //        switch (tmp_load_cmd_info->load_cmd->cmd) {
    //            case LC_SEGMENT_64:
    //                if (!parse_LC_SEGMENT_64(tmp_load_cmd_info))
    //                    return FALSE;
    //                break;
    //            case LC_SYMTAB:
    //                if (!parse_LC_SYMTAB(tmp_load_cmd_info))
    //                    return FALSE;
    //                break;
    //            case LC_LOAD_DYLINKER:
    //                if (!parse_LC_LOAD_DYLINKER(tmp_load_cmd_info))
    //                    return FALSE;
    //                break;
    //            case LC_FUNCTION_STARTS:
    //                if (!parse_LC_FUNCTION_STARTS(tmp_load_cmd_info))
    //                    return FALSE;
    //                break;
    //            default:
    //                break;
    //        }
    //    }

    for (const auto &load_command_info : this->loadcommands.load_command_infos)
    {
        switch (load_command_info.load_cmd->cmd)
        {
        case LC_SEGMENT_64:
            if (!parse_LC_SEGMENT_64(&load_command_info))
                return FALSE;
            break;
        case LC_SYMTAB:
            if (!parse_LC_SYMTAB(&load_command_info))
                return FALSE;
            break;
        case LC_LOAD_DYLINKER:
            if (!parse_LC_LOAD_DYLINKER(&load_command_info))
                return FALSE;
            break;
        case LC_FUNCTION_STARTS:
            if (!parse_LC_FUNCTION_STARTS(&load_command_info))
                return FALSE;
            break;
        default:
            break;
        }
    }
    return TRUE;
}

// set linkedit bias
// how to calculate it?
// REF: dyld-421.2/src/ImageLoaderMachO.cpp
// ImageLoaderMachO::parseLoadCmds
// fLinkEditBase = (uint8_t*)(segActualLoadAddress(i) - segFileOffset(i));

bool Macho::parse_LC_SEGMENT_64(const load_command_info_t *load_cmd_info)
{
    Sdebug("start dump LC_SEGMENT_64...");
    struct segment_command_64 *seg_cmd;
    zaddr tmp_addr;
    segment_command_64_info_t *seg_cmd_info;

    seg_cmd = (struct segment_command_64 *)load_cmd_info->cmd_info;
    tmp_addr = load_cmd_info->fileoff;
    seg_cmd_info = new segment_command_64_info_t();

    seg_cmd_info->seg_cmd_64 = seg_cmd;
    seg_cmd_info->fileoff = seg_cmd->fileoff;
    seg_cmd_info->vmaddr = seg_cmd->vmaddr;

    if (strcmp(seg_cmd->segname, "__TEXT") == 0)
    {
        this->load_vmaddr = seg_cmd->vmaddr;
    }

    if ((this->input.type == TASK_INPUT) || (this->input.type == MEM_INPUT))
    {
        if (strcmp(seg_cmd->segname, "__LINKEDIT") == 0)
        {
            this->linkedit_base = seg_cmd->vmaddr + this->aslr_slide - seg_cmd->fileoff;
        }

        if (strcmp(seg_cmd->segname, "__TEXT") == 0)
        {
            this->aslr_slide = this->load_addr - seg_cmd->vmaddr;
            // check integrity
            assert(this->load_addr == seg_cmd->vmaddr + this->aslr_slide);
        }

        // set load end addr
        if (seg_cmd->vmaddr + this->aslr_slide + seg_cmd->vmsize > this->load_end_addr)
        {
            this->load_end_addr = seg_cmd->vmaddr + this->aslr_slide + seg_cmd->vmsize;
        }

        Xdebug("segment: %s's vmaddr: 0x%llx", seg_cmd->segname,
               seg_cmd->vmaddr + this->aslr_slide);
    }

    /* iterate dump section */
    section_64_info_t sect_info;
    struct section_64 *sect_64;
    tmp_addr = tmp_addr + sizeof(struct segment_command_64);

    for (uint32_t nsect = 0; nsect < seg_cmd->nsects; nsect++)
    {
        sect_64 = (struct section_64 *)malloc(sizeof(struct section_64));
        macho_runtime_read(tmp_addr, sect_64, sizeof(section_64));

        Xdebug("\t section: %s's runtime addr: 0x%lx", sect_64->sectname, tmp_addr);

        sect_info.sect_64 = sect_64;
        sect_info.vmaddr = sect_64->addr;
        sect_info.offset = sect_64->offset;

        seg_cmd_info->sect_64_infos.push_back(sect_info);
        this->loadcommands.section_infos.push_back(sect_info);
        tmp_addr += sizeof(struct section_64);
    }

    this->loadcommands.segment_command_64_infos.push_back(*seg_cmd_info);
    return TRUE;
}

bool Macho::parse_LC_SYMTAB(const load_command_info_t *load_cmd_info)
{
    Sdebug("start dump LC_SYMTAB...");

    struct symtab_command *sym_cmd =
        (struct symtab_command *)load_cmd_info->cmd_info;

    if (this->isRuntime)
    {
        this->linkinfo.symtab_rtaddr = this->linkedit_base + sym_cmd->symoff;
        this->linkinfo.strtab_rtaddr = this->linkedit_base + sym_cmd->stroff;
    }

    this->linkinfo.symtab_offset = sym_cmd->symoff;
    this->linkinfo.strtab_offset = sym_cmd->stroff;

    struct nlist_64 *nlist;
    nlist = (struct nlist_64 *)malloc(sizeof(struct nlist_64));

    zaddr tmp_addr = macho_link_address(this->linkinfo.symtab_offset);
    for (int i = 0; i < sym_cmd->nsyms; i++)
    {
        macho_read(tmp_addr, nlist, sizeof(struct nlist_64));
        if (nlist->n_un.n_strx > 1)
        {
            char *sym_name = macho_read_string(macho_link_address(this->linkinfo.strtab_offset + nlist->n_un.n_strx));
            if (sym_name)
            {
                if (!strcmp(sym_name, "_dlopen"))
                {
                    Xinfo("found function _dlopen: 0x%llx", this->load_addr + nlist->n_value);
                }
                //                if(nl->n_type == N_FUN) {
                //                    std::cout << "[+] function: " << sym_name << ",
                //                    address: 0x" << std::hex << nl->n_value <<
                //                    std::endl;
                //                }
                //                if(nl->n_type & 0x1e) {
                //                    std::cout << "[+] extern function: " << sym_name
                //                    << ", address: 0x" << std::hex << nl->n_value <<
                //                    std::endl;
                //                }
                free(sym_name);
            }
            else
            {
                // Generate an interrupt
                Serror("symbol read error at parse_LC_SYMTAB");
            }
        }
        tmp_addr += sizeof(struct nlist_64);
    }

    return TRUE;
}

bool Macho::parse_LC_LOAD_DYLINKER(const load_command_info_t *load_cmd_info)
{
    struct dylinker_command *dy_cmd;
    dy_cmd = (struct dylinker_command *)load_cmd_info->cmd_info;
    this->dyld_path =
        macho_runtime_read_string(load_cmd_info->fileoff + dy_cmd->name.offset);
    return TRUE;
}

bool Macho::parse_LC_FUNCTION_STARTS(const load_command_info_t *load_cmd_info)
{
    Sdebug("start dump LC_FUNCTION_STARTS...");
    struct linkedit_data_command *func_start_cmd;
    const uint8_t *infoStart = NULL;
    const uint8_t *infoEnd;

    func_start_cmd = (struct linkedit_data_command *)load_cmd_info->cmd_info;

    infoStart = (uint8_t *)(macho_link_address(func_start_cmd->dataoff));
    infoEnd = &infoStart[func_start_cmd->datasize];

    zaddr tmp = 0;
    unsigned n = 0;
    zaddr func_vmaddr = this->load_vmaddr;
    for (const uint8_t *p = infoStart; (*p != 0) && (p < infoEnd);)
    {
        uint8_t tmp_uleb128[8];

        macho_read((zaddr)p, tmp_uleb128, 8);
        func_vmaddr += decodeULEB128(tmp_uleb128, &n);
        p += n;
        Xdebug("ubleb128: %p", (zpointer)func_vmaddr);

        func_info_t *func_info = new func_info_t();

        func_info->func_vmaddr = func_vmaddr;

        objc_method_info_t *objc_method_info =
            hash_search_method_addr(&this->objcruntime.objc_method_infos_map, func_info->func_vmaddr);
        // objc_method_info_t * objc_method_info =
        // search_method_addr(this->objcruntime.objc_method_infos, addr);

        if (objc_method_info)
        {
            func_info->func_type = CLASS_FUNC;
            func_info->class_method = objc_method_info;
        }
        else
        {
            func_info->func_type = DEFAULT_FUNC;
            func_info->class_method = NULL;
        }
        this->objcruntime.funcs.push_back(func_info);
    }
    return TRUE;
}
