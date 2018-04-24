#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SaitamaKit/CommonKit/log/log_kit.h>

#define DEFAULT_ALLOCATOR_CAPACITY 4

ExecuteMemoryManager *ExecuteMemoryManagerSharedInstance() {
    if (!MemoryHelperIsSupportAllocateRXMemory())
        return NULL;

    ExecuteMemoryManager *emm;
    emm = (ExecuteMemoryManager *)malloc0(sizeof(ExecuteMemoryManager));
    emm->execute_memory_block_ptr_list =
        (ExecuteMemoryBlock **)malloc0(sizeof(ExecuteMemoryBlock *) * DEFAULT_ALLOCATOR_CAPACITY);
    if (!emm->execute_memory_block_ptr_list)
        return NULL;
    emm->size     = 0;
    emm->capacity = DEFAULT_ALLOCATOR_CAPACITY;
    return emm;
}

static ExecuteMemoryBlock *AllocateExecuteMemoryPage() {
    zz_size_t page_size     = MemoryHelperGetPageSize();
    zz_ptr_t page_ptr       = NULL;
    ExecuteMemoryBlock *emb = NULL;

    page_ptr = MemoryHelperAllocatePage(1);
    if (!page_ptr) {
        return NULL;
    }
    if (!MemoryHelperProtectAsExecutable((zz_addr_t)page_ptr, page_size)) {
        ERROR_LOG("MemoryHelperProtectAsExecutable error at %p", page_ptr);
    }

    emb                  = (ExecuteMemoryBlock *)malloc0(sizeof(ExecuteMemoryBlock));
    emb->start_address   = page_ptr;
    emb->current_address = page_ptr;
    emb->total_size      = page_size;
    emb->used_size       = 0;
    return emb;
}

ExecuteMemoryBlock *AllocateNearExecuteMemoryPage(zz_addr_t address, zz_size_t redirect_range_size) {
    zz_size_t page_size     = MemoryHelperGetPageSize();
    zz_ptr_t page_ptr       = NULL;
    ExecuteMemoryBlock *emb = NULL;

    page_ptr = MemoryHelperAllocateNearPage(address, redirect_range_size, 1);
    if (!page_ptr) {
        return NULL;
    }

    if (!MemoryHelperProtectAsExecutable((zz_addr_t)page_ptr, page_size)) {
        ERROR_LOG("MemoryHelperProtectAsExecutable error at %p", page_ptr);
        ZZ_DEBUG_BREAK();
        exit(1);
    }

    emb = (ExecuteMemoryBlock *)malloc0(sizeof(ExecuteMemoryBlock));

    emb->start_address = page_ptr;

    if ((zz_addr_t)page_ptr > address && ((zz_addr_t)page_ptr + page_size) > (address + redirect_range_size)) {
        emb->total_size      = (address + redirect_range_size) - (zz_addr_t)page_ptr;
        emb->used_size       = 0;
        emb->current_address = page_ptr;
    } else if ((zz_addr_t)page_ptr < address && (zz_addr_t)page_ptr < (address - redirect_range_size)) {
        emb->total_size      = page_size;
        emb->used_size       = (address - redirect_range_size) - (zz_addr_t)page_ptr;
        emb->current_address = (zz_ptr_t)(address - redirect_range_size);
    } else {
        emb->total_size      = page_size;
        emb->used_size       = 0;
        emb->current_address = page_ptr;
    }
    emb->is_code_cave = FALSE;
    return emb;
}

static ExecuteMemoryBlock *AllocateNearCodeCave(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t cave_size) {
    zz_size_t page_size     = MemoryHelperGetPageSize();
    zz_ptr_t cave_ptr       = NULL;
    ExecuteMemoryBlock *emb = NULL;

    cave_ptr = MemoryHelperSearchCodeCave(address, redirect_range_size, cave_size);

    if (!cave_ptr)
        return NULL;

    emb                  = (ExecuteMemoryBlock *)malloc0(sizeof(ExecuteMemoryBlock));
    emb->start_address   = cave_ptr;
    emb->current_address = cave_ptr;
    emb->total_size      = cave_size;
    emb->used_size       = 0;
    emb->is_code_cave    = TRUE;
    return emb;
}

RetStatus ExecuteMemoryManagerAdd(ExecuteMemoryManager *emm, ExecuteMemoryBlock *emb) {
    if (!emm)
        return RS_FAILED;
    if (emm->size >= emm->capacity) {
        ExecuteMemoryBlock **execute_memory_block_ptr_list =
            realloc(emm->execute_memory_block_ptr_list, sizeof(ExecuteMemoryBlock) * (emm->capacity) * 2);
        if (!execute_memory_block_ptr_list) {
            return RS_FAILED;
        }
        emm->capacity                      = emm->capacity * 2;
        emm->execute_memory_block_ptr_list = execute_memory_block_ptr_list;
    }
    emm->execute_memory_block_ptr_list[emm->size++] = emb;
    return RS_SUCCESS;
}

//  1. try allocate from the history pages
//  2. try allocate a new emb
//  3. add it to the emb manager
CodeSlice *ExecuteMemoryManagerAllocateCodeSlice(ExecuteMemoryManager *emm, zz_size_t cs_size) {
    CodeSlice *cs           = NULL;
    ExecuteMemoryBlock *emb = NULL;
    int i;

    for (i = 0; i < emm->size; i++) {
        emb = emm->execute_memory_block_ptr_list[i];

        if ((zz_addr_t)emb->current_address % 4) {
            int t = 4 - (zz_addr_t)emb->current_address % 4;
            emb->used_size += t;
            emb->current_address += t;
        }

        if (emb->start_address && !emb->is_code_cave && (emb->total_size - emb->used_size) > cs_size) {
            cs       = (CodeSlice *)malloc0(sizeof(CodeSlice));
            cs->data = emb->current_address;
            cs->size = cs_size;

            emb->current_address += cs_size;
            emb->used_size += cs_size;
            return cs;
        }
    }

    emb = AllocateExecuteMemoryPage();
    ExecuteMemoryManagerAdd(emm, emb);

    if ((zz_addr_t)emb->current_address % 4) {
        int t = 4 - (zz_addr_t)emb->current_address % 4;
        emb->used_size += t;
        emb->current_address += t;
    }

    cs       = (CodeSlice *)malloc0(sizeof(CodeSlice));
    cs->data = emb->current_address;
    cs->size = cs_size;

    emb->current_address += cs_size;
    emb->used_size += cs_size;

    return cs;
}

//  1. try allocate from the history pages
//  2. try allocate a new near emb
//  3. add it to the emb manager
CodeSlice *ExecuteMemoryManagerAllocateNearCodeSlice(ExecuteMemoryManager *emm, zz_addr_t address,
                                                     zz_size_t redirect_range_size, zz_size_t cs_size) {
    CodeSlice *cs           = NULL;
    ExecuteMemoryBlock *emb = NULL;
    int i;
    for (i = 0; i < emm->size; i++) {
        emb = emm->execute_memory_block_ptr_list[i];
        // 1. emb is initialized
        // 2. can't be codecave
        // 3. the rest memory of this emb is enough for cs_size
        // 4. the emb address is near
        if (emb->start_address && !emb->is_code_cave) {
            int flag             = 0;
            zz_addr_t split_addr = 0;

            if ((zz_addr_t)emb->current_address < address) {
                if (address - redirect_range_size < (zz_addr_t)emb->current_address) {
                    // enough for cs_size
                    if ((emb->total_size - emb->used_size) < cs_size)
                        continue;
                    flag = 1;
                } else if (address - redirect_range_size > (zz_addr_t)emb->current_address &&
                           (address - redirect_range_size) < ((zz_addr_t)emb->start_address + emb->total_size)) {
                    // enough for cs_size
                    if (((zz_addr_t)emb->start_address + emb->total_size) - (address - redirect_range_size) < cs_size)
                        continue;
                    split_addr = address - redirect_range_size;
                    flag       = 2;
                }
            } else {
                if (address + redirect_range_size > ((zz_addr_t)emb->start_address + emb->total_size)) {
                    // enough for cs_size
                    if ((emb->total_size - emb->used_size) < cs_size)
                        continue;
                    flag = 1;
                } else if ((address + redirect_range_size) > (zz_addr_t)emb->current_address &&
                           (address + redirect_range_size) < ((zz_addr_t)emb->start_address + emb->total_size)) {
                    if ((address + redirect_range_size) - (zz_addr_t)emb->current_address > cs_size)
                        continue;
                    flag = 1;
                }
            }

            if (1 == flag) {
                cs               = (CodeSlice *)malloc0(sizeof(CodeSlice));
                cs->is_code_cave = emb->is_code_cave;
                cs->data         = emb->current_address;
                cs->size         = cs_size;

                emb->current_address += cs_size;
                emb->used_size += cs_size;
                return cs;
            } else if (2 == flag) {

                // new emb
                ExecuteMemoryBlock *new_emb = (ExecuteMemoryBlock *)malloc0(sizeof(ExecuteMemoryBlock));
                new_emb->start_address      = (zz_ptr_t)split_addr;
                new_emb->total_size               = ((zz_addr_t)emb->start_address + emb->total_size) - split_addr;
                new_emb->used_size          = 0;
                new_emb->current_address    = (zz_ptr_t)split_addr;
                ExecuteMemoryManagerAdd(emm, new_emb);

                // origin emb
                emb->total_size = split_addr - (zz_addr_t)emb->start_address;

                cs               = (CodeSlice *)malloc0(sizeof(CodeSlice));
                cs->is_code_cave = FALSE;
                cs->data         = new_emb->current_address;
                cs->size         = cs_size;

                new_emb->current_address += cs_size;
                new_emb->used_size += cs_size;
                return cs;
            }
        }
    }

#if 0
    emb = ExecuteMemoryManagerTryAddNearExecuteMemoryPage(address, redirect_range_size);
    // try allocate again, avoid the boundary emb
    if (emb && (emb->total_size - emb->used_size) < cs_size) {
        emb = ExecuteMemoryManagerTryAddNearExecuteMemoryPage(address, redirect_range_size);
    }
#endif
    emb = NULL;

    if (!emb) {
        emb = AllocateNearCodeCave(address, redirect_range_size, cs_size);
        if (!emb)
            return NULL;
    }
    if (!emb)
        return NULL;

    cs               = (CodeSlice *)malloc0(sizeof(CodeSlice));
    cs->is_code_cave = emb->is_code_cave;
    cs->data         = emb->current_address;
    cs->size         = cs_size;

    emb->current_address += cs_size;
    emb->used_size += cs_size;

    return cs;
}
