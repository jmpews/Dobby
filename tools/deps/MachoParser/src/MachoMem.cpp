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

// macho
#include <mach-o/loader.h>
#include <mach/mach_traps.h>
#include <mach/mach.h>

// common
#include <assert.h>
#include <unistd.h>

#include "MachoMem.h"
#include "zz.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "zzdeps/darwin/memory-utils-darwin.h"
#include "zzdeps/darwin/macho-utils-darwin.h"
#ifdef __cplusplus
}
#endif

MachoMem::MachoMem() : MachoRuntime()
{
    this->input.type = MEM_INPUT;
    searchBinLoadAddress();
}

MachoMem::MachoMem(input_t input) : MachoRuntime(input) {}

MachoMem::MachoMem(zaddr load_addr) : MachoRuntime()
{
    this->load_addr = this->load_addr;
    this->input.type = MEM_INPUT;
    this->input.mem.baseAddr = this->load_addr;
}

bool MachoMem::macho_read(zaddr addr, zpointer data, zsize len)
{
    memcpy(data, (zpointer)addr, len);
    return TRUE;
}

char *MachoMem::macho_read_string(zaddr addr)
{
    return zz_vm_read_string((zpointer)addr);
}

bool Macho::check_initialization()
{
    if (this->input.mem.baseAddr <= 0)
    {
        Sdebug("MachoMem need init.");
        return FALSE;
    }
    return TRUE;
}

bool MachoMem::searchBinLoadAddress()
{
    // search align by memory page

    zsize page_size;
    unsigned long search_block_size;
    zsize aslr_limit;
    zaddr cur_addr, end_addr;

    page_size = sysconf(_SC_PAGESIZE);
    search_block_size = 0x1000;
    search_block_size = page_size;

    cur_addr = MACHO_LOAD_ADDRESS;
    aslr_limit = ((1 << 16) << 12) + 0x100000000;
    end_addr = MACHO_LOAD_ADDRESS + aslr_limit;

    char ch;
    while (end_addr > cur_addr)
    {
        if (zz_posix_vm_check_address_valid_via_msync((const zpointer)cur_addr))
        {
            this->load_addr = cur_addr;
            this->input.mem.baseAddr = cur_addr;
            Xinfo("macho load at %p", (zpointer)cur_addr);
            return TRUE;
        }
        cur_addr += search_block_size;
    }
    Serror("searchBinLoadAddress failed.");
    return FALSE;
}

// /* brute force search dyld */
// bool MachoMem::search_dyld_load_address(zaddr dyld_vm_addr)
// {
//     zaddr start_addr, cur_addr, end_addr;
//     zaddr task_info_dyld_addr;
//     zsize search_block_size;
//     uint32_t magic_64;
//     zsize aslr_limit;
//     zsize page_size;

//     aslr_limit = ((1 << 16) << 12);
//     page_size = sysconf(_SC_PAGESIZE);
//     search_block_size = 0x1000;
//     search_block_size = page_size;
//     magic_64 = MH_MAGIC_64;

//     if (this->load_end_addr == 0)
//         start_addr = MACHO_LOAD_ADDRESS;
//     else
//         start_addr = this->load_end_addr;

//     if (dyld_vm_addr)
//     {
//         end_addr = dyld_vm_addr + aslr_limit;
//         start_addr = dyld_vm_addr;
//     }
//     else
//     {
//         start_addr = start_addr;
//         end_addr = (start_addr + aslr_limit) & (~(search_block_size - 1));
//     }

//     // search align by memory page

//     /*
//       LINE: xnu-3789.41.3:mach_loader.c:383 dyld_aslr_offset
//       two condition!!!

//       1. dyld no vm_addr
//       LINE: xnu-3789.41.3:mach_loader.c:649
//       LINE: xnu-3789.41.3:mach_loader.c:718
//       slide = vm_map_round_page(slide + binresult->max_vm_addr,
//      effective_page_mask);

//       2. dyld do have vm_addr
//       LINE: xnu-3789.41.3:mach_loader.c:1364
//       vm_offset = scp->vmaddr + slide;
//    */
//     char *buf = (char *)malloc(sizeof(uint32_t));

//     cur_addr = start_addr;

//     Xdebug("start dyld search range(0x%lx, 0x%lx).", start_addr, end_addr);

//     while (end_addr > cur_addr)
//     {
//         // ATTENTION !!! this function is conflict with LLDB, reason is below.
//         // lldb is still catch EXC_BAD_ACCESS, without lldb is ok.
//         // or you can use `zz_check_address_valid_by_mem` replace
//         // https://stackoverflow.com/questions/26829119/how-to-make-lldb-ignore-exc-bad-access-exception
//         if (zz_posix_vm_check_address_valid_via_signal((const zpointer)cur_addr))
//             if (macho_read(cur_addr, buf, sizeof(uint32_t)))
//             {
//                 if ((!memcmp(buf, &magic_64, sizeof(uint32_t))) &&
//                     check_dyld_arch(cur_addr))
//                     break;
//             }

//         cur_addr += search_block_size;
//     }

//     task_info_dyld_addr = (zaddr)zz_macho_get_dyld_load_address_via_task(mach_task_self());
//     Xdebug("task_info() dyld_addr: %p", (zpointer)task_info_dyld_addr);

//     if (cur_addr < end_addr)
//     {
//         assert(task_info_dyld_addr == cur_addr);
//         m_dyld_load_addr = cur_addr;
//         return TRUE;
//     }
//     else
//     {
//         m_dyld_load_addr = task_info_dyld_addr;
//         Serror("[!] search_dyld_load_address failed. use task_info().");
//         return FALSE;
//     }
// }

// bool MachoMem::check_dyld_arch(zaddr dyld_load_addr)
// {
//     MachoMem dyld(dyld_load_addr);
//     // dyld.load_addr = dyld_load_addr;
//     // dyld.input.mem.baseAddr = dyld_load_addr;

//     Xdebug("dyld load address check at %p", (zpointer)dyld_load_addr);
//     do
//     {
//         if (!dyld.parse_header())
//             break;
//         if (dyld.is64bit)
//         {
//             if (dyld.header.header64->filetype != MH_DYLINKER)
//                 break;
//             if (!dyld.parse_load_command_headers())
//                 break;
//             if (!dyld.isDyldLinker)
//                 break;
//         }
//         else
//             break;
//         return TRUE;
//     } while (0);
//     return FALSE;
// }

// bool MachoMem::parse_dyld()
// {
//     MachoFD *dyld_fd;
//     zaddr dyld_vm_addr;
//     MachoFD *dyld_64_fd;

//     dyld_fd = new MachoFD();

//     if (dyld_fd->setPath(this->dyld_path))
//     {
//         dyld_fd->parse_type = PARSE_SIMPLE;
//         dyld_fd->parse_macho();
//         if (dyld_fd->isFat)
//         {
//             dyld_64_fd = new MachoFD();
//             dyld_64_fd = (MachoFD *)dyld_fd->parse_macho_arch(CPU_TYPE_X86_64);
//             dyld_64_fd->parse_type = PARSE_SIMPLE;
//             dyld_64_fd->parse_macho();
//             dyld_vm_addr = dyld_64_fd->this->load_vmaddr;
//         }
//     }
//     else
//     {
//         Serror("parse dyld failed");
//         dyld_vm_addr = 0;
//     }
//     search_dyld_load_address(dyld_vm_addr);
//     Xinfo("dyld load at %p", (zpointer)m_dyld_load_addr);
//     return TRUE;
// }
