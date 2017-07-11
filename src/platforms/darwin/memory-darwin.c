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

#include <mach/vm_statistics.h>
#include <sys/mman.h>
#include <mach/error.h>
#include <mach/vm_map.h>

/*
    mach_task_self()
 */
#include <mach/mach.h>
#include <unistd.h>

#include "memory-darwin.h"
#include "darwin/mach_vm.h"

zpointer alloc_page(zsize page_size)
{
    mach_vm_address_t result;
    kern_return_t kr;

    kr = mach_vm_allocate(mach_task_self(), &result, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        return NULL;
    }
    return (zpointer)result;
}

void make_page_executable(zpointer page_ptr, zuint page_size)
{
    mach_error_t err = err_none;
    long _page_size = sysconf(_SC_PAGESIZE);
    zpointer _page_ptr = (zpointer)((vm_address_t)page_ptr & ~(_page_size - 1));

    err = mprotect(_page_ptr, page_size, PROT_EXEC | PROT_READ);
    if (err)
    {
        Xerror("err = %x", err);
    }

    mach_error_t prot_err = err_none;
    prot_err = mach_vm_protect(mach_task_self(),
                               (vm_address_t)page_ptr, page_size, false,
                               (VM_PROT_READ | VM_PROT_EXECUTE));
    if (prot_err)
        Xerror("err = %x", err);
}

void make_page_writable(zpointer page_ptr, zuint page_size)
{
    mach_error_t err = err_none;
    //	Make the original function implementation writable.
    
    // int c = (VM_PROT_ALL | VM_PROT_COPY);
    // mach_vm_protect((vm_map_t)mach_task_self(), (mach_vm_address_t)page_ptr, 16, false, VM_PROT_READ);
    err = mach_vm_protect(mach_task_self(),
                          (mach_vm_address_t)page_ptr, page_size, false,
                          (VM_PROT_ALL | VM_PROT_COPY));
    if (err)
        err = mach_vm_protect(mach_task_self(),
                              (mach_vm_address_t)page_ptr, page_size, false,
                              (VM_PROT_DEFAULT | VM_PROT_COPY));

    if (err)
    {
        Xerror("err = %x", err);
    }
}
