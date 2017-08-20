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

#include "../../../include/zz.h"
#include "../../../include/hookzz.h"

#include <mach/vm_prot.h>
#include <mach/mach_types.h>


zpointer zz_vm_allocate_pages(zsize n_pages);
zpointer zz_vm_allocate_near_pages(zaddr address, zsize range_size, zsize n_pages);
zpointer zz_vm_allocate(zsize size);
bool zz_vm_patch_code(const zaddr address, const zpointer codedata, zuint codedata_size);
bool zz_vm_protect_as_executable(const zaddr address, zsize size);
bool zz_vm_protect_as_writable(const zaddr address, zsize size);
zpointer zz_vm_search_text_code_cave(zaddr address, zsize range_size, zsize size);