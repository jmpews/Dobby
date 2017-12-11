#ifndef zzdeps_linux_memory_utils_linux_h
#define zzdeps_linux_memory_utils_linux_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "../zz.h"

zz_ptr_t zz_linux_vm_search_code_cave(zz_addr_t address, zz_size_t range_size, zz_size_t size);

#endif