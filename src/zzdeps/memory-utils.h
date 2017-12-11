#ifndef zzdeps_memory_utils_h
#define zzdeps_memory_utils_h

#include "zz.h"

typedef struct _MemoryLayout {
    int size;
    struct {
        int flags;
        zz_ptr_t start;
        zz_ptr_t end;
    } mem[4096];
} MemoryLayout;

#endif