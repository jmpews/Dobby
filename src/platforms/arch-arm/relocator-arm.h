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

#ifndef platforms_arch_arm_relocator_arm_h
#define platforms_arch_arm_relocator_arm_h

#include "hookzz.h"
#include "kitzz.h"

#include "memory.h"
#include "writer.h"

#include "instructions.h"
#include "reader-arm.h"
#include "regs-arm.h"
#include "writer-arm.h"

typedef struct _ZzARMRelocator {
    bool try_relocated_again;
    zz_size_t try_relocated_length;
    zz_ptr_t input_start;
    zz_ptr_t input_cur;
    zz_addr_t input_pc;
    int inpos;
    int outpos;
    ZzInstruction *input_insns;
    ZzRelocateInstruction *output_insns;
    ZzLiteralInstruction **relocate_literal_insns;
    zz_size_t relocate_literal_insns_size;
    ZzARMAssemblerWriter *output;
} ZzARMRelocator;

void zz_arm_relocator_init(ZzARMRelocator *relocator, zz_ptr_t input_code, ZzARMAssemblerWriter *output);

void zz_arm_relocator_free(ZzARMRelocator *relocator);

void zz_arm_relocator_reset(ZzARMRelocator *self, zz_ptr_t input_code, ZzARMAssemblerWriter *output);

void zz_arm_relocator_write_all(ZzARMRelocator *self);

zz_size_t zz_arm_relocator_read_one(ZzARMRelocator *self, ZzInstruction *instruction);

void zz_arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes);

bool zz_arm_relocator_write_one(ZzARMRelocator *self);

void zz_arm_relocator_relocate_writer(ZzARMRelocator *relocator, zz_addr_t code_address);

#endif