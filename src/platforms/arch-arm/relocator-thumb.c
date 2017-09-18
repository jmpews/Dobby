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

#include <string.h>

#include "relocator-thumb.h"

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_thumb_relocator_init(ZzThumbRelocator *relocator, zpointer input_code,
                             ZzThumbWriter *writer) {
    cs_err err;
    err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &relocator->capstone);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }
    cs_option(relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);

    relocator->input_start = input_code;
    relocator->input_cur = input_code;
    relocator->input_insns = (Instruction *)malloc(
        MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));
}

zsize zz_thumb_relocator_read_one(ZzThumbRelocator *self,
                                  Instruction *instruction) {
    cs_insn **cs_insn_ptr, *cs_insn;
    Instruction insn = self->input_insns[self->inpos];
    cs_insn_ptr = &insn.cs_insn;

    if (cs_disasm(self->capstone, self->input_cur, 4, self->input_pc, 1,
                  cs_insn_ptr) != 1) {
        return 0;
    }

    cs_insn = *cs_insn_ptr;

    switch (cs_insn->id) {}

    self->inpos++;

    if (instruction != NULL)
        *instruction = insn;

    self->input_cur += cs_insn->size;
    self->input_pc += cs_insn->size;

    return self->input_cur - self->input_start;
}

void zz_thumb_relocator_try_relocate(zpointer address, zuint min_bytes,
                                     zuint *max_bytes) {
    *max_bytes = 16;
    return;
}