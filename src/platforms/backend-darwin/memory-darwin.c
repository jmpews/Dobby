/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <mach/mach.h>

#include "memory-darwin.h"

zz_size_t ZzMemoryGetPageSzie() { return zz_posix_vm_get_page_size(); }

zz_ptr_t ZzMemoryAllocatePages(zz_size_t n_pages) { return zz_vm_allocate_pages_via_task(mach_task_self(), n_pages); }

zz_ptr_t ZzMemoryAllocateNearPages(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t n_pages) {
    return zz_vm_allocate_near_pages_via_task(mach_task_self(), address, redirect_range_size, n_pages);
}

zz_ptr_t ZzMemoryAllocate(zz_size_t size) { return zz_vm_allocate_via_task(mach_task_self(), size); }

bool ZzMemoryPatchCode(const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size) {
    return zz_vm_patch_code_via_task(mach_task_self(), address, codedata, codedata_size);
}

bool ZzMemoryProtectAsExecutable(const zz_addr_t address, zz_size_t size) {

    return zz_vm_protect_as_executable_via_task(mach_task_self(), address, size);
}

bool ZzMemoryProtectAsWritable(const zz_addr_t address, zz_size_t size) {
    return zz_vm_protect_as_writable_via_task(mach_task_self(), address, size);
}

zz_ptr_t ZzMemorySearchCodeCave(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t size) {
    // return zz_vm_search_text_code_cave_via_dylibs(address, redirect_range_size, size);
    return zz_vm_search_code_cave(address, redirect_range_size, size);
}

bool ZzMemoryIsSupportAllocateRXPage() { return zz_vm_can_allocate_rx_page(); }