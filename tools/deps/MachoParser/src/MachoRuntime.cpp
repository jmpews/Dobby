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

#include "MachoRuntime.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "zzdeps/common/LEB128.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/darwin/memory-utils-darwin.h"
#ifdef __cplusplus
}
#endif

MachoRuntime::MachoRuntime() : Macho()
{
    /* runtime var */
    this->aslr_slide = 0;
    this->linkedit_base = 0;
    this->load_end_addr = 0;
    this->load_addr = 0;

    this->isRuntime = TRUE;
}

MachoRuntime::MachoRuntime(input_t input) : Macho(input)
{
    /* runtime var */
    this->aslr_slide = 0;
    this->linkedit_base = 0;
    this->load_end_addr = 0;
    this->load_addr = 0;

    this->isRuntime = TRUE;
}

bool MachoRuntime::parse_macho()
{
    Sdebug("start dump macho...");
    do
    {
        if (!check_initialization())
        {
            break;
        }
        if (!parse_header())
            break;

        parse_load_command_headers();
        parse_load_command_details();

        return TRUE;
    } while (0);
    return FALSE;
}

void MachoRuntime::print_macho()
{
    Sinfo("print runtime macho:");

    Xinfo("image base: %p", (zpointer)this->load_addr);
    Xinfo("string table address: %p", (zpointer)this->linkinfo.strtab_rtaddr);
    if (!this->isDyldLinker)
        Xinfo("dyld path: %s", this->dyld_path);

    Xinfo("dump %lu classes", this->objcruntime.objc_class_infos.size());
    Xinfo("dump %lu funcs", this->objcruntime.funcs.size());
    Xinfo("dump %lu class-methods", this->objcruntime.objc_method_infos.size());

    zsize default_func_count = 0;
    std::vector<func_info_t *>::iterator iter;
    func_info_t *func_info;
    for (iter = this->objcruntime.funcs.begin(); iter != this->objcruntime.funcs.end(); iter++)
    {
        func_info = (*iter);
        if (func_info->func_type == DEFAULT_FUNC)
        {
            default_func_count++;
        }
    }
    Xinfo("dump %lu default-funcs(c/c++)(iter)", default_func_count);
}
