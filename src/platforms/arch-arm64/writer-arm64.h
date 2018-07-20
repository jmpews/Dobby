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

#ifndef platforms_arch_arm64_writer_arm64_h
#define platforms_arch_arm64_writer_arm64_h

#include "instruction.h"
#include "register-arm64.h"
#include "writer-arm64.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _ARM64AssemblyWriter {
  void *start_pc;
  void *start_address;

  list_t *instCTXs;
  buffer_array_t *inst_bytes;
} ARM64AssemblyWriter;

#define arm64_assembly_writer_cclass(member) cclass(arm64_assembly_writer, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
ARM64AssemblyWriter *arm64_assembly_writer_cclass(new)(void *pc);
void arm64_assembly_writer_cclass(destory)(ARM64AssemblyWriter *self);
void arm64_assembly_writer_cclass(reset)(ARM64AssemblyWriter *self, void *pc);
void arm64_assembly_writer_cclass(patch_to)(ARM64AssemblyWriter *self, void *target_address);

/* b xxx range for near jump */
size_t arm64_assembly_writer_cclass(bxxx_range)();

void arm64_assembly_writer_cclass(put_bytes)(ARM64AssemblyWriter *self, void *data, int length);

void arm64_assembly_writer_cclass(put_ldr_reg_imm)(ARM64AssemblyWriter *self, ARM64Reg reg, uint32_t offset);
void arm64_assembly_writer_cclass(put_str_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg src_reg,
                                                          ARM64Reg dest_reg, uint64_t offset);
void arm64_assembly_writer_cclass(put_ldr_reg_reg_offset)(ARM64AssemblyWriter *self, ARM64Reg dest_reg,
                                                          ARM64Reg src_reg, uint64_t offset);
void arm64_assembly_writer_cclass(put_br_reg)(ARM64AssemblyWriter *self, ARM64Reg reg);
void arm64_assembly_writer_cclass(put_blr_reg)(ARM64AssemblyWriter *self, ARM64Reg reg);
void arm64_assembly_writer_cclass(put_b_imm)(ARM64AssemblyWriter *self, uint64_t offset);
#ifdef __cplusplus
}
#endif //__cplusplus
#endif