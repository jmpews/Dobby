#ifndef zzdeps_common_memory_utils_common_h
#define zzdeps_common_memory_utils_common_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "../zz.h"

char *zz_vm_read_string(const zpointer address);
zpointer zz_vm_search_data(const zpointer start_addr, const zpointer end_addr,
                        zbyte *data, zsize data_len);
#endif