#include "MemoryManager.h"

CodeSlice *MemoryManager::allocateCodeSlice(int size) {
    CodeSlice *cs = NULL;
    for (auto fmb : free_memory_blocks) {
        if ((fmb->total_size - fmb->used_size) > size) {
            cs       = new (CodeSlice);
            cs->data = (void *)(fmb->address + fmb->used_size);
            cs->size = size;

            fmb->used_size += size;
            return cs;
        }
    }

    if (cs == NULL) {
        void *page_ptr       = allocateMemoryPage(3, 1);
        FreeMemoryBlock *fmb = new (FreeMemoryBlock);
        fmb->used_size       = 0;
        fmb->total_size      = PageSize() * 1;
        fmb->prot            = MEM_RX;
        fmb->address         = (zz_addr_t)page_ptr;
        free_memory_blocks.push_back(fmb);

        fmb->used_size += size;
        cs       = new (CodeSlice);
        cs->data = (void *)(fmb->address + fmb->used_size);
        cs->size = size;
        return cs;
    }
}

void *search_code_cave(zz_addr_t search_start, zz_addr_t search_end, int size) {
    assert(search_start);
    assert(search_start < search_end);

    zz_addr_t curr_addr         = search_start;
    unsigned char dummy_0[1024] = {0};

    while (curr_addr < search_end) {
        if (!memcpy((void *)curr_addr, dummy_0, size)) {
            return (void *)curr_addr;
        }

        curr_addr += size;
    }
    return NULL;
}

CodeCave *MemoryManager::searchCodeCave(void *address, int range, int size) {
    CodeCave *cc = NULL;

    zz_addr_t limit_start, limit_end;
    zz_addr_t search_start, search_end;

    limit_start = (zz_addr_t)address - range;
    limit_start = (zz_addr_t)address + range - size;
    for (auto mb : process_memory_layout) {
        search_start = mb->address > limit_start ? mb->address : limit_start;
        search_end   = (mb->address + mb->size) < limit_end ? (mb->address + mb->size) : limit_end;
        void *p      = search_dummy_code_cave(search_start, search_end, size);
        if (p) {
            cc          = new (CodeCave);
            cc->size    = size;
            cc->address = (zz_addr_t)p;
            return cc;
        }
    }
    return NULL;
}
