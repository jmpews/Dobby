#ifndef emm_h
#define emm_h

#include <stdint.h>

#include "hookzz.h"
#include "zkit.h"

#include "CommonKit/log/log_kit.h"

#include "memory.h"

typedef struct _codeslice {
    zz_ptr_t data;
    zz_size_t size;
    bool is_used;
    bool is_code_cave;
} CodeSlice;

typedef struct _ExecuteMemoryBlock {
    zz_ptr_t start_address;
    zz_ptr_t current_address;
    zz_size_t total_size;
    zz_size_t used_size;
    bool is_code_cave;
} ExecuteMemoryBlock;

typedef struct _ExecuteMemoryManager {
    ExecuteMemoryBlock **execute_memory_block_ptr_list;
    zz_size_t size;
    zz_size_t capacity;
} ExecuteMemoryManager;

CodeSlice *ExecuteMemoryManagerAllocateNearCodeSlice(ExecuteMemoryManager *emm, zz_addr_t address,
                                                     zz_size_t redirect_range_size, zz_size_t codeslice_size);

CodeSlice *ExecuteMemoryManagerAllocateCodeSlice(ExecuteMemoryManager *emm, zz_size_t codeslice_size);

ExecuteMemoryManager *ExecuteMemoryManagerSharedInstance();

#endif