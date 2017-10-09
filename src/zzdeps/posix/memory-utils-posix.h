#ifndef zzdeps_posix_memory_utils_posix_h
#define zzdeps_posix_memory_utils_posix_h

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../common/memory-utils-common.h"
#include "../zz.h"

zsize zz_posix_vm_get_page_size();

zbool zz_posix_vm_check_address_valid_via_msync(const zpointer p);

zbool zz_posix_vm_check_address_valid_via_signal(zpointer p);

zbool zz_posix_vm_protect(const zaddr address, zsize size, int page_prot);

zbool zz_posix_vm_protect_as_executable(const zaddr address, zsize size);

zbool zz_posxi_vm_protect_as_writable(const zaddr address, zsize size);

zpointer zz_posix_vm_allocate_pages(zsize n_pages);

zpointer zz_posix_vm_allocate(zsize size);

zpointer zz_posix_vm_allocate_near_pages(zaddr address, zsize range_size, zsize n_pages);

zpointer zz_posix_vm_search_text_code_cave(zaddr address, zsize range_size, zsize size);

zbool zz_posix_vm_patch_code(const zaddr address, const zpointer codedata, zuint codedata_size);

#endif