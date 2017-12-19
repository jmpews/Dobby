
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "kitzz.h"

#include "CommonKit/memory/common_memory_kit.h"

zz_size_t zz_posix_vm_get_page_size();

bool zz_posix_vm_check_address_valid_via_msync(const zz_ptr_t p);

bool zz_posix_vm_check_address_valid_via_signal(zz_ptr_t p);

bool zz_posix_vm_protect(const zz_addr_t address, zz_size_t size, int page_prot);

bool zz_posix_vm_protect_as_executable(const zz_addr_t address, zz_size_t size);

bool zz_posxi_vm_protect_as_writable(const zz_addr_t address, zz_size_t size);

zz_ptr_t zz_posix_vm_allocate_pages(zz_size_t n_pages);

zz_ptr_t zz_posix_vm_allocate(zz_size_t size);

zz_ptr_t zz_posix_vm_allocate_near_pages(zz_addr_t address, zz_size_t range_size, zz_size_t n_pages);

zz_ptr_t zz_posix_vm_search_text_code_cave(zz_addr_t address, zz_size_t range_size, zz_size_t size);

bool zz_posix_vm_patch_code(const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size);
