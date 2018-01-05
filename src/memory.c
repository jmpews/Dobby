/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "memory.h"

#include <stdlib.h>
#include <string.h>

void *zz_malloc_with_zero(zz_size_t size) {
    void *tmp = (void *)malloc(size);
    memset(tmp, 0, size);
    return tmp;
}

ZZSTATUS ZzRuntimeCodePatch(void *address, void *codedata, unsigned long codedata_size) {
    zz_addr_t address_aligned = (zz_addr_t)address & ~(zz_addr_t)1;
    if (!ZzMemoryPatchCode(address_aligned, codedata, codedata_size))
        return ZZ_FAILED;
    return ZZ_SUCCESS;
}