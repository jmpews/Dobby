//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef memory_h
#define memory_h

#include "hookzz.h"
#include "kitzz.h"

void *zz_malloc_with_zero(zz_size_t size);

zz_size_t ZzMemoryGetPageSzie();

zz_ptr_t ZzMemoryAllocatePages(zz_size_t n_pages);

zz_ptr_t ZzMemoryAllocateNearPages(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t n_pages);

zz_ptr_t ZzMemoryAllocate(zz_size_t size);

bool ZzMemoryPatchCode(const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size);

bool ZzMemoryProtectAsExecutable(const zz_addr_t address, zz_size_t size);

bool ZzMemoryProtectAsWritable(const zz_addr_t address, zz_size_t size);

bool ZzMemoryIsSupportAllocateRXPage();

zz_ptr_t ZzMemorySearchCodeCave(zz_addr_t address, zz_size_t redirect_range_size, zz_size_t size);

#endif