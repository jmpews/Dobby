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

#ifndef zzdeps_common_memory_utils_common_h
#define zzdeps_common_memory_utils_common_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "../zz.h"

char *zz_vm_read_string(const zz_ptr_t address);

zz_ptr_t zz_vm_search_data(const zz_ptr_t start_addr, const zz_ptr_t end_addr, zbyte *data,
                           zz_size_t data_len);

zz_addr_t zz_vm_align_floor(zz_addr_t address, zz_size_t range_size);

zz_addr_t zz_vm_align_ceil(zz_addr_t address, zz_size_t range_size);

#endif