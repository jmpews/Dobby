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

#include <mach/mach_types.h>

#include <iostream>
#include <vector>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <mach-o/nlist.h>

#include <assert.h>

#include "zz.h"
#include "Macho.h"
#include "MachoFD.h"

bool Macho::parse_header()
{
    uint32_t magic;
    if (!macho_read(this->load_addr, &magic, sizeof(uint32_t)))
        return FALSE;

    switch (magic)
    {
    case MH_MAGIC_64:
        this->is64bit = TRUE;
        header.header64 = (struct mach_header_64 *)malloc(sizeof(struct mach_header_64));
        if (!macho_read(this->load_addr, header.header64, sizeof(struct mach_header_64)))
            return FALSE;
        Sdebug("dump arch-64");
        break;

    case FAT_CIGAM:
    case FAT_MAGIC:
        this->isFat = TRUE;
        header.fat_header = (struct fat_header *)malloc(sizeof(struct fat_header));
        if (!macho_read(this->load_addr, header.fat_header, sizeof(struct fat_header)))
            return FALSE;
        Sdebug("dump arch-fat");
        break;
    default:
        Serror("only support x86_64.");
        return FALSE;
    }
    return TRUE;
}

bool MachoFD::parse_universal()
{
    if (this->input.type != FD_INPUT)
    {
        Serror("[!] input must be fd");
        return FALSE;
    }
    zaddr addr = this->load_addr + sizeof(struct fat_header);
    uint32_t nfat = OSSwapBigToHostInt32(header.fat_header->nfat_arch);

    for (uint32_t i = 0; i < nfat; i++)
    {
        struct fat_arch *arch = (struct fat_arch *)malloc(sizeof(struct fat_arch));
        macho_read(addr + i * sizeof(struct fat_arch), arch, sizeof(struct fat_arch));

        size_t length = OSSwapBigToHostInt32(arch->size);

        input_t t;
        memcpy(&t, &this->input, sizeof(input_t));
        t.type = FD_INPUT;
        t.fd.data = (zpointer)((zaddr)this->input.fd.data + OSSwapBigToHostInt32(arch->offset));
        t.fd.baseAddr = (zaddr)t.fd.data;

        MachoFD *macho = new MachoFD(t);
        macho->load_addr = (zaddr)macho->input.fd.data;
        macho->input.fd = this->input.fd;

        fat_arch_info_t fat_arch_info;
        fat_arch_info.arch = arch;
        fat_arch_info.macho = macho;

        header.fat_arch_infos.push_back(fat_arch_info);
    }
    return TRUE;
}

MachoFD *MachoFD::parse_macho_arch(int arch)
{
    if (this->input.type != FD_INPUT)
    {
        Serror("input must be fd");
        return NULL;
    }

    // TODO:
    //#if defined(__x86_64__)
    //    arch = CPU_TYPE_X86_64;
    //#elif defined(__arm64__)
    //    arch = CPU_TYPE_ARM64;
    //#endif

    std::vector<fat_arch_info_t>::iterator iter;
    fat_arch_info_t *fat_arch_info;
    for (iter = header.fat_arch_infos.begin(); iter != header.fat_arch_infos.end(); iter++)
    {
        fat_arch_info = &(*iter);
        // TODO:
        if (OSSwapBigToHostInt32(fat_arch_info->arch->cputype) == arch)
        {
            return (MachoFD *)(fat_arch_info->macho);
        }
    }
    return NULL;
}
