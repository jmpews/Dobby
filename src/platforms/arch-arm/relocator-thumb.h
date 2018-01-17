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

#ifndef platforms_arch_arm_relocator_thumb_h
#define platforms_arch_arm_relocator_thumb_h

#include "hookzz.h"
#include "kitzz.h"

#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-thumb.h"
#include "regs-arm.h"
#include "writer-thumb.h"

typedef struct _ZzThumbRelocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    zz_ptr_t input_start;
    zz_ptr_t input_cur;
    zz_addr_t input_pc;
    ZzInstruction *input_insns;
    ZzRelocateInstruction *output_insns;
    ZzLiteralInstruction **relocate_literal_insns;
    zz_size_t relocate_literal_insns_size;
    ZzThumbAssemblerWriter *output;
    int inpos;
    int outpos;
} ZzThumbRelocator;

void zz_thumb_relocator_init(ZzThumbRelocator *relocator, zz_ptr_t input_code, ZzThumbAssemblerWriter *writer);

void zz_thumb_relocator_reset(ZzThumbRelocator *self, zz_ptr_t input_code, ZzThumbAssemblerWriter *output);

zz_size_t zz_thumb_relocator_read_one(ZzThumbRelocator *self, ZzInstruction *instruction);

bool zz_thumb_relocator_write_one(ZzThumbRelocator *self);

void zz_thumb_relocator_relocate_writer(ZzThumbRelocator *relocator, zz_addr_t code_address);

void zz_thumb_relocator_write_all(ZzThumbRelocator *self);

void zz_thumb_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

#endif