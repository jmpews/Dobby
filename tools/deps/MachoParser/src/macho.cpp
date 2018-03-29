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

// dyld
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach_types.h>

// objc
#include <objc/runtime.h>

// common
#include <assert.h>
#include <pthread.h>

#include "Macho.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "zzdeps/common/LEB128.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/darwin/memory-utils-darwin.h"
#ifdef __cplusplus
}
#endif

#include "zz.h"

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

Macho::Macho() {
    this->is64bit      = FALSE;
    this->isDyldLinker = FALSE;
    this->dyld_path    = NULL;
    this->isFat        = FALSE;

    this->image_base  = 0;
    this->load_vmaddr = 0;

    /* runtime var */
    this->aslr_slide    = 0;
    this->linkedit_base = 0;
    this->load_end_addr = 0;
    this->load_addr     = 0;

    this->parse_type = PARSE_ALL;
}

Macho::Macho(input_t input) : Macho() { memcpy(&this->input, &input, sizeof(input_t)); }

// bool Macho::check_initialization()
// {
//     if (this->input.type == FD_INPUT)
//     {
//         if (this->input.fd.fd <= 0)
//         {
//             Serror("MachoParser must be init.");
//             return FALSE;
//         }
//     }
//     else if (this->input.type == TASK_INPUT)
//     {
//         if (this->input.rt.pid <= 0)
//         {
//             Serror("MachoParser must be init.");
//             return FALSE;
//         }
//     }
//     else if (this->input.type == MEM_INPUT)
//     {
//         if (this->input.mem.baseAddr <= 0)
//         {
//             Serror("MachoParser must be init.");
//             return FALSE;
//         }
//         return TRUE;
//     }
//     return TRUE;
// }

// bool Macho::parse_macho()
// {
//     Sdebug("start dump macho...");
//     do
//     {
//         if (!check_initialization())
//         {
//             break;
//         }
//         if (!parse_header())
//             break;

//         if (this->isFat)
//         {
//             parse_universal();
//         }
//         else
//         {
//             parse_load_command_headers();
//             parse_load_command_details();
//         }

//         return TRUE;
//     } while (0);
//     return FALSE;
// }

// void Macho::print_macho()
// {
//     Sinfo("print macho...");
//     if (this->input.type == FD_INPUT)
//     {
//         Xinfo("__TEXT segment vm_addr: %p", (zpointer)this->load_vmaddr);
//     }
//     Xinfo("string table addr: %p", (zpointer)this->strtab_addr);
//     Xinfo("symbol table addr: %p", (zpointer)this->symtab_addr);
//     if (!this->isDyldLinker)
//         Xinfo("dyld path: %s.", this->dyld_path);
//     if (this->input.type == MEM_INPUT || this->input.type == TASK_INPUT)
//     {
//         Xinfo("dump %lu classes", this->objcruntime.objc_class_infos.size());
//         Xinfo("dump %lu funcs", this->objcruntime.funcs.size());
//         Xinfo("dump %lu class-methods", this->objcruntime.objc_method_infos.size());

//         unsigned int default_func_count = 0;
//         std::vector<func_info_t *>::iterator iter;
//         func_info_t *func_info;
//         for (iter = this->objcruntime.funcs.begin(); iter != this->objcruntime.funcs.end(); iter++)
//         {
//             func_info = (*iter);
//             if (func_info->func_type == DEFAULT_FUNC)
//             {
//                 // Xinfo("## %p", func_info->func_addr);
//                 default_func_count++;
//             }
//         }
//         // Xinfo("dump %u default-funcs(c/c++)",
//         // this->objcruntime.funcs.size()-this->objcruntime.objc_method_infos.size());
//         Xinfo("dump %u default-funcs(c/c++)(iter)", default_func_count);
//     }
// }

// bool Macho::macho_read(zaddr addr, zpointer data, zsize len)
// {
//     if (this->input.type == TASK_INPUT)
//     {
//         task_t task = this->input.rt.task;
//         return zz_darwin_vm_read_data_via_task(task, (zaddr)addr, data, len);
//     }
//     else if (this->input.type == FD_INPUT)
//     {
//         if (addr - (zaddr)this->input.fd.data > this->input.fd.length)
//         {
//             Serror("macho_read over.");
//             return FALSE;
//         }
//         memcpy(data, (zpointer)addr, len);
//         return TRUE;
//     }
//     else if (this->input.type == MEM_INPUT)
//     {
//         memcpy(data, (zpointer)addr, len);
//         return TRUE;
//     }
//     else
//     {
//         Serror("unknown input.");
//     }
//     return TRUE;
// }

zaddr Macho::macho_search_data(const zaddr start_addr, const zaddr end_addr, const zbyte *data, const zsize len) {
    zaddr search_start_addr, search_end_addr, search_curr_addr;
    zbyte *buf;

    search_start_addr = start_addr;
    search_end_addr   = end_addr;

    if (search_start_addr < this->load_addr) {
        search_start_addr = this->load_addr;
    }
    if (search_end_addr > this->load_end_addr) {
        search_end_addr = this->load_end_addr;
    }

    search_curr_addr = search_start_addr;
    buf              = (zbyte *)malloc(len);

    while (search_end_addr > search_curr_addr) {
        if (this->macho_read(search_curr_addr, buf, len))
            if (!memcmp(buf, data, len)) {
                return search_curr_addr;
            }
        search_curr_addr += len;
    }
    return 0;
}

// char *Macho::macho_read_string(zaddr addr)
// {
//     if (this->input.type == FD_INPUT)
//     {
//         return zz_vm_read_string((zpointer)addr);
//     }
//     else if (this->input.type == MEM_INPUT)
//     {
//         return zz_vm_read_string((zpointer)addr);
//     }
//     else if (this->input.type == TASK_INPUT)
//     {
//         return zz_darwin_vm_read_string_via_task(this->input.rt.task, (zaddr)addr);
//     }
//     else
//     {
//         Serror("unknown input.");
//     }
//     return NULL;
// }

// bool Macho::macho_read_fake_aslr(zaddr addr, zpointer data, zsize len)
// {
//     if (this->input.type == FD_INPUT)
//         return macho_read(addr + this->aslr_slide, data, len);
//     else if (this->input.type == TASK_INPUT)
//         return macho_read(addr, data, len);
//     else if (this->input.type == MEM_INPUT)
//         return macho_read(addr, data, len);
//     return TRUE;
// }

// char *Macho::macho_read_string_fake_aslr(zaddr addr)
// {
//     if (this->input.type == FD_INPUT)
//         return macho_read_string(addr + this->aslr_slide);
//     else if (this->input.type == TASK_INPUT)
//         return macho_read_string(addr);
//     else if (this->input.type == MEM_INPUT)
//         return macho_read_string(addr);
//     return NULL;
// }

bool Macho::macho_runtime_read(zaddr vmaddr, zpointer data, zsize len) {
    zaddr tmp_vmaddr = macho_runtime_address(vmaddr);
    if (this->input.type == FD_INPUT)
        return macho_read(tmp_vmaddr, data, len);
    else if (this->input.type == TASK_INPUT)
        return macho_read(tmp_vmaddr, data, len);
    else if (this->input.type == MEM_INPUT)
        return macho_read(tmp_vmaddr, data, len);
    return TRUE;
}
char *Macho::macho_runtime_read_string(zaddr vmaddr) {
    zaddr tmp_vmaddr = macho_runtime_address(vmaddr);

    if (this->input.type == FD_INPUT)
        return macho_read_string(tmp_vmaddr + this->aslr_slide);
    else if (this->input.type == TASK_INPUT)
        return macho_read_string(tmp_vmaddr);
    else if (this->input.type == MEM_INPUT)
        return macho_read_string(tmp_vmaddr);
    return NULL;
}
zaddr Macho::macho_runtime_address(zaddr vmaddr) {
    if ((this->input.type == TASK_INPUT) || (this->input.type == MEM_INPUT))
        return vmaddr;
    else {
        return vmaddr - this->load_vmaddr + this->load_addr;
    }
}
zaddr Macho::macho_link_address(zaddr vmaddr) {
    if ((this->input.type == TASK_INPUT) || (this->input.type == MEM_INPUT))
        return vmaddr + this->linkedit_base;
    else {
        return vmaddr + this->load_addr;
    }
}