#include "memory_manager.h"
#include "core.h"
#include "std_kit/std_list.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* shared instance */
memory_manager_t *g_memory_manager = NULL;
memory_manager_t *memory_manager_cclass(shared_instance)() {
    if (g_memory_manager == NULL) {
        g_memory_manager                        = SAFE_MALLOC_TYPE(memory_manager_t);
        g_memory_manager->code_caves            = list_new();
        g_memory_manager->free_memory_blocks    = list_new();
        g_memory_manager->process_memory_layout = list_new();
        XCHECK(g_memory_manager != NULL);
    }
    return g_memory_manager;
}

CodeSlice *memory_manager_cclass(allocate_code_slice)(memory_manager_t *self, int size) {
    CodeSlice *cs       = NULL;
    list_iterator_t *it = list_iterator_new(self->free_memory_blocks, LIST_HEAD);
    for (int i = 0; i < self->free_memory_blocks->len; i++) {
        FreeMemoryBlock *fmb = (FreeMemoryBlock *)(list_at(self->free_memory_blocks, i)->val);
        if ((fmb->total_size - fmb->used_size) > size) {
            cs       = SAFE_MALLOC_TYPE(CodeSlice);
            cs->data = (void *)(fmb->address + fmb->used_size);
            cs->size = size;

            fmb->used_size += size;
            return cs;
        }
    }

    // allocate a new page
    if (cs == NULL) {
        void *page_ptr       = memory_manager_cclass(allocate_page)(self, PROT_R_X, 1);
        FreeMemoryBlock *fmb = SAFE_MALLOC_TYPE(FreeMemoryBlock);
        fmb->used_size       = 0;
        fmb->total_size      = memory_manager_cclass(get_page_size)();
        fmb->prot            = PROT_R_X;
        fmb->address         = page_ptr;
        list_rpush(self->free_memory_blocks, list_node_new(fmb));

        cs       = SAFE_MALLOC_TYPE(CodeSlice);
        cs->data = (void *)(fmb->address + fmb->used_size);
        cs->size = size;

        fmb->used_size += size;
        return cs;
    }
    return NULL;
}

void *search_dummy_code_cave(zz_addr_t search_start, zz_addr_t search_end, int size) {
    assert(search_start);
    assert(search_start < search_end);

    zz_addr_t cur_addr          = search_start;
    unsigned char dummy_0[1024] = {0};

    while (cur_addr < search_end) {
        if (!memcpy((void *)cur_addr, dummy_0, size)) {
            return (void *)cur_addr;
        }

        cur_addr += size;
    }
    return NULL;
}

CodeCave *memory_manager_cclass(search_code_cave)(memory_manager_t *self, void *address, int range, int size) {
    CodeCave *cc = NULL;
    zz_addr_t limit_start, limit_end;
    zz_addr_t search_start, search_end;

    limit_start         = (zz_addr_t)address - range;
    limit_start         = (zz_addr_t)address + range - size;
    list_iterator_t *it = list_iterator_new(self->free_memory_blocks, LIST_HEAD);
    for (int i = 0; i < self->process_memory_layout->len; i++) {
        MemoryBlock *mb = (MemoryBlock *)(list_at(self->process_memory_layout, i)->val);
        search_start    = (zz_addr_t)mb->address > limit_start ? (zz_addr_t)mb->address : limit_start;
        search_end = ((zz_addr_t)mb->address + mb->size) < limit_end ? ((zz_addr_t)mb->address + mb->size) : limit_end;
        void *p    = search_dummy_code_cave(search_start, search_end, size);
        if (p) {
            cc          = SAFE_MALLOC_TYPE(CodeCave);
            cc->size    = size;
            cc->address = p;
            return cc;
        }
    }
    return NULL;
}