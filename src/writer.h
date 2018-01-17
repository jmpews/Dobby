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

#ifndef writer_h
#define writer_h

#include "hookzz.h"
#include "kitzz.h"

#define MAX_LITERAL_INSN_SIZE 128

// literal instruction
typedef struct _ZzLiteralInstruction {
    zz_ptr_t literal_insn_ptr;
    zz_addr_t *literal_address_ptr;
} ZzLiteralInstruction;

typedef struct _ZzAssemblerWriter {
    zz_ptr_t codedata; // writer temporary buffer
    zz_ptr_t base;     // dest
    zz_addr_t pc;      // current pc register
    zz_size_t size;

    ZzLiteralInstruction literal_insns[MAX_LITERAL_INSN_SIZE]; // literal instruction set
    zz_size_t literal_insn_size;
} ZzAssemblerWriter;

#endif
