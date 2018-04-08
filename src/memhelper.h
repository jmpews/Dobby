#ifndef memory_h
#define memory_h

#include "hookzz.h"
#include "zkit.h"

void *malloc0(zz_size_t size);

zz_size_t MemoryHelperGetPageSize();

zz_ptr_t MemoryHelperAllocatePage(zz_size_t count);

zz_ptr_t MemoryHelperAllocateNearPage(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t count);

bool MemoryHelperPatchCode(const zz_addr_t address, const zz_ptr_t code, zz_size_t code_size);

bool MemoryHelperProtectAsExecutable(const zz_addr_t address, zz_size_t size);

bool MemoryHelperIsSupportAllocateRXMemory();

zz_ptr_t MemoryHelperSearchCodeCave(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t cave_size);

#endif