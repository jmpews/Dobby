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

#include "../../../../zz.h"
#include "../../../include/hookzz.h"


#include <mach/vm_prot.h>

zpointer zz_alloc_memory(zsize size);
zpointer zz_alloc_pages(zsize n_pages);
ZZSTATUS zz_mprotect(zpointer addr, zsize size, vm_prot_t page_prot);
void make_page_executable(zpointer page_ptr, zuint page_size);
void make_page_writable(zpointer page_ptr, zuint page_size);
void memory_patch_code(zpointer addr, zpointer code_ptr, zuint code_size);