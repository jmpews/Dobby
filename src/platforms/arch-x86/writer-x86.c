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

#include <stdlib.h>
#include <string.h>

#include "writer-x86.h"

ZzX86Writer *zz_x86_writer_new(zz_ptr_t data_ptr) { return NULL; }

void zz_x86_writer_init(ZzX86Writer *self, zz_ptr_t target_addr) { zz_x86_writer_reset(self, target_addr); }

void zz_x86_writer_reset(ZzX86Writer *self, zz_ptr_t data_ptr) {}

zz_size_t zz_x86_writer_near_jump_range_size() { return 0; }

void zz_x86_writer_put_bytes(ZzAssemblerWriter *self, char *data, zz_size_t size) {}

void zz_x86_writer_put_instruction(ZzAssemblerWriter *self, uint32_t insn) {}

// ======= relocator =======

// ======= user custom =======

// ======= default =======
