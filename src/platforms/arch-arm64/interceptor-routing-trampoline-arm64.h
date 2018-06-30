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

#ifndef interceptor_routing_trampoline_arm64_h
#define interceptor_routing_trampoline_arm64_h

#include "hookzz.h"
#include "interceptor.h"
#include "memory_manager.h"
#include "reader-arm64.h"
#include "relocator-arm64.h"
#include "writer-arm64.h"

#define CTX_SAVE_STACK_OFFSET (8 + 30 * 8 + 8 * 16)

typedef struct _interceptor_backend_arm64_t {
    memory_manager_t *memory_manager;
    ARM64Relocator *relocator_arm64;
    ARM64AssemblyWriter *writer_arm64;
    ARM64AssemblyReader *reader_arm64;
} interceptor_backend_arm64_t;

typedef struct _hook_entry_backend_arm64_t {
    int limit_relocate_inst_size;
} hook_entry_backend_arm64_t;

#endif