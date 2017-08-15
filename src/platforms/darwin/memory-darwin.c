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

#if defined(__x86_64__)
#include <mach/mach_vm.h>
#elif defined(__arm64__)
#include "../../zzdeps/darwin/mach_vm.h"
#endif

#include "../../zzdeps/common/debugbreak.h"
#include "memory-darwin.h"
#include "../../zzdeps/darwin/memory-utils-darwin.h"

/*
  ref:
  substitute/lib/darwin/execmem.c:execmem_foreign_write_with_pc_patch
  frida-gum-master/gum/gummemory.c:gum_memory_patch_code

  frida-gum-master/gum/backend-darwin/gummemory-darwin.c:gum_alloc_n_pages

  mach mmap use __vm_allocate and __vm_map
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/hurd/mmap.c
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/munmap.c

  http://shakthimaan.com/downloads/hurd/A.Programmers.Guide.to.the.Mach.System.Calls.pdf
*/
bool zz_vm_patch_code_via_task(task_t task, const zaddr address, const zpointer codedata, zuint codedata_size)
{
    zsize page_size;
    zaddr start_page_addr, end_page_addr;
    zsize page_offset, range_size;

    page_size = zz_vm_get_page_size();
    /*
      https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
     */
    start_page_addr = (address) & ~(page_size - 1);
    end_page_addr = ((address + codedata_size - 1)) & ~(page_size - 1);
    page_offset = address - start_page_addr;
    range_size = (end_page_addr + page_size) - start_page_addr;

    vm_prot_t prot;
    vm_inherit_t inherit;
    kern_return_t kr;
    mach_port_t task_self = mach_task_self();

    if (!zz_vm_get_page_info_via_task(task_self, (const zaddr)start_page_addr, &prot, &inherit))
    {
        return false;
    }

    /*
      another method, pelease read `REF`;

     */
    // zpointer code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    zpointer code_mmap = zz_vm_allocate_via_task(task_self, range_size);

    kr = vm_copy(task_self, start_page_addr, range_size,
                 (vm_address_t)code_mmap);

    if (kr != KERN_SUCCESS)
    {
        KR_ERROR_AT(kr, start_page_addr);
        return false;
    }
    memcpy(code_mmap + page_offset, codedata, codedata_size);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    if (!zz_vm_protect_via_task(task_self, (zaddr)code_mmap, range_size, prot))
        return false;

    // TODO: need check `memory region` again.
    /*
        TODO:
        // if only this, `memory region` is `r-x`
        vm_protect((vm_map_t)mach_task_self(), 0x00000001816b2030, 16, false, 0x13);
        // and with this, `memory region` is `rwx`
        *(char *)0x00000001816b01a8 = 'a';
     */

    mach_vm_address_t target = (zaddr)start_page_addr;
    vm_prot_t c, m;
    kr = mach_vm_remap(task_self, &target, range_size, 0, VM_FLAGS_OVERWRITE,
                       task_self, (mach_vm_address_t)code_mmap, /*copy*/ true, &c, &m,
                       inherit);

    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return false;
    }
    /*
      read `REF`
     */
    // munmap(code_mmap, range_size);
    kr = mach_vm_deallocate(task_self, (zaddr)code_mmap, range_size);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return false;
    }
    return true;
}

zpointer zz_vm_allocate_pages(zsize n_pages)
{
    return zz_vm_allocate_pages_via_task(mach_task_self(), n_pages);
}

zpointer zz_vm_allocate(zsize size)
{
    return zz_vm_allocate_via_task(mach_task_self(), size);
}

bool zz_vm_patch_code(const zaddr address, const zpointer codedata, zuint codedata_size)
{
    return zz_vm_patch_code_via_task(mach_task_self(), address, codedata, codedata_size);
}

bool zz_vm_protect_as_executable(const zaddr address, zsize size)
{

    return zz_vm_protect_as_executable_via_task(mach_task_self(), address, size);
}
bool zz_vm_protect_as_writable(const zaddr address, zsize size)
{
    return zz_vm_protect_as_writable_via_task(mach_task_self(), address, size);
}