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
    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &relocator->capstone);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }
    cs_option(relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);

    relocator->inpos = 0;
    relocator->outpos = 0;

    relocator->input_start = input_code;
    relocator->input_cur = input_code;
    relocator->input_pc = (zaddr)input_code;
    relocator->input_insns =
        (Instruction *)malloc(MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));
    memset(relocator->input_insns, 0, MAX_RELOCATOR_INSTRUCIONS_SIZE * sizeof(Instruction));
}

void zz_thumb_relocator_reset(ZzThumbRelocator *self, zpointer input_code, ZzThumbWriter *output) {
    self->input_cur = input_code;
    self->input_start = input_code;
    self->input_pc = (zaddr)input_code;

    self->inpos = 0;
    self->outpos = 0;

    self->output = output;
}

zsize zz_thumb_relocator_read_one(ZzThumbRelocator *self, Instruction *instruction) {
    cs_insn **cs_insn_ptr, *cs_insn;
    Instruction *insn = &self->input_insns[self->inpos];
    cs_insn_ptr = &insn->cs_insn;

    if (*cs_insn_ptr == NULL)
        *cs_insn_ptr = cs_malloc(self->capstone);

    // http://www.capstone-engine.org/iteration.html
    uint64_t address;
    size_t size;
    const uint8_t *code;

    code = self->input_cur;
    size = 4;
    address = self->input_pc;
    cs_insn = *cs_insn_ptr;

    if (!cs_disasm_iter(self->capstone, &code, &size, &address, cs_insn)) {
        return 0;
    }

    switch (cs_insn->id) {}

    self->inpos++;

    if (instruction != NULL)
        instruction = insn;

    self->input_cur += cs_insn->size;
    self->input_pc += cs_insn->size;

    return self->input_cur - self->input_start;
}

void zz_thumb_relocator_try_relocate(zpointer address, zuint min_bytes, zuint *max_bytes) {
    *max_bytes = 16;
    return;
}

void zz_thumb_relocator_write_all(ZzThumbRelocator *self) {
    zuint count = 0;
    while (zz_thumb_relocator_write_one(self))
        count++;
}

zbool zz_thumb_relocator_write_one(ZzThumbRelocator *self) {
    Instruction *insn;
    cs_insn *cs_insn;
    zbool rewritten = false;

    insn = &self->input_insns[self->outpos];
    cs_insn = insn->cs_insn;

    if (self->inpos != self->outpos) {
        self->outpos++;
    } else {
        return false;
    }

    switch (cs_insn->id) {}
    if (!rewritten)
        zz_thumb_writer_put_bytes(self->output, cs_insn->bytes, cs_insn->size);
    return true;
}