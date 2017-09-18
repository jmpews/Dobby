#ifndef zzdeps_posix_memory_utils_posix_h
#define zzdeps_posix_memory_utils_posix_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../zz.h"
#include "../common/memory-utils-common.h"

zsize zz_posix_vm_get_page_size();

zbool zz_vm_check_address_valid_via_msync(const zpointer p);

zbool zz_posix_vm_check_address_valid_via_signal(zpointer p);

#endif