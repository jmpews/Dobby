#ifndef memory_h
#define memory_h

#include "hookzz.h"
#include "zkit.h"

void *malloc0(zz_size_t size);

zz_size_t MemoryHelperGetPageSize();

zz_ptr_t MemoryHelperAllocatePage(zz_size_t n_pages);

zz_ptr_t MemoryHelperAllocateNearPage(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t n_pages);

zz_ptr_t MemoryAllocate(zz_size_t size);

bool MemoryHelperPatchCode(const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size);

bool MemoryHelperProtectAsExecutable(const zz_addr_t address, zz_size_t size);

bool MemoryHelperProtectAsWritable(const zz_addr_t address, zz_size_t size);

bool MemoryHelperIsSupportAllocateRXMemory();

zz_ptr_t MemoryHelperSearchCodeCave(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t size);

#endif