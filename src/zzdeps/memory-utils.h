#ifndef zzdeps_memory_utils_h
#define zzdeps_memory_utils_h

#include "zz.h"

typedef struct _MemoryLayout {
    int size;
    struct {
        int flags;
        zpointer start;
        zpointer end;
    } mem[128];
} MemoryLayout;

#endif