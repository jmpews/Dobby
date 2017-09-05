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

#include <mach/error.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>

#include "zzdeps/common/debugbreak.h"

#include "memory-darwin.h"
#include "zzdeps/darwin/memory-utils-darwin.h"

zsize ZzMemoryGetPageSzie() {
    return zz_posix_vm_get_page_size();
}

zpointer ZzMemoryAllocatePages(zsize n_pages) {
    return zz_vm_allocate_pages_via_task(mach_task_self(), n_pages);
}

zpointer ZzMemoryAllocateNearPages(zaddr address, zsize range_size, zsize n_pages) {
    return zz_vm_allocate_near_pages_via_task(mach_task_self(), address, range_size, n_pages);
}

zpointer ZzMemoryAllocate(zsize size) {
    return zz_vm_allocate_via_task(mach_task_self(), size);
}

bool ZzMemoryPatchCode(const zaddr address, const zpointer codedata, zuint codedata_size) {
    return zz_vm_patch_code_via_task(mach_task_self(), address, codedata, codedata_size);
}

bool ZzMemoryProtectAsExecutable(const zaddr address, zsize size) {

    return zz_vm_protect_as_executable_via_task(mach_task_self(), address, size);
}

bool ZzMemoryProtectAsWritable(const zaddr address, zsize size) {
    return zz_vm_protect_as_writable_via_task(mach_task_self(), address, size);
}

zpointer ZzMemorySearchCodeCave(zaddr address, zsize range_size, zsize size) {
    // return zz_vm_search_text_code_cave_via_dylibs(address, range_size, size);
    return zz_vm_search_code_cave_via_recurse(address, range_size, size);
}