/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef included_asm_x86_h
#define included_asm_x86_h

typedef union {
  struct {
    u8 code;
    u8 type;
  };
  u8 data[2];
} x86_insn_operand_t;

typedef struct {
  /* Instruction name. */
  char *name;

  /* X86 instructions may have up to 3 operands. */
  x86_insn_operand_t operands[3];

  u16 flags;
#define X86_INSN_FLAG_DEFAULT_64_BIT         (1 << 0)
#define X86_INSN_FLAG_SET_SSE_GROUP(n)       ((n) << 5)
#define X86_INSN_FLAG_GET_SSE_GROUP(f)       (((f) >> 5) & 0x1f)
#define X86_INSN_FLAG_SET_MODRM_REG_GROUP(n) (((n)&0x3f) << 10)
#define X86_INSN_FLAG_GET_MODRM_REG_GROUP(f) (((f) >> 10) & 0x3f)
} x86_insn_t;

always_inline uword x86_insn_operand_is_valid(x86_insn_t *i, uword o) {
  ASSERT(o < ARRAY_LEN(i->operands));
  return i->operands[o].code != '_';
}

#define foreach_x86_legacy_prefix                                                                                      \
  _(OPERAND_SIZE, 0x66)                                                                                                \
  _(ADDRESS_SIZE, 0x67)                                                                                                \
  _(SEGMENT_CS, 0x2e)                                                                                                  \
  _(SEGMENT_DS, 0x3e)                                                                                                  \
  _(SEGMENT_ES, 0x26)                                                                                                  \
  _(SEGMENT_FS, 0x64)                                                                                                  \
  _(SEGMENT_GS, 0x65)                                                                                                  \
  _(SEGMENT_SS, 0x36)                                                                                                  \
  _(LOCK, 0xf0)                                                                                                        \
  _(REPZ, 0xf3)                                                                                                        \
  _(REPNZ, 0xf2)

#define foreach_x86_insn_parse_flag                                                                                    \
  /* Parse in 32/64-bit mode. */                                                                                       \
  _(PARSE_32_BIT, 0)                                                                                                   \
  _(PARSE_64_BIT, 0)                                                                                                   \
  _(IS_ADDRESS, 0)                                                                                                     \
  /* regs[1/2] is a valid base/index register */                                                                       \
  _(HAS_BASE, 0)                                                                                                       \
  _(HAS_INDEX, 0)                                                                                                      \
  /* rex w bit */                                                                                                      \
  _(OPERAND_SIZE_64, 0)

typedef enum {
#define _(f, o) X86_INSN_FLAG_BIT_##f,
  foreach_x86_insn_parse_flag foreach_x86_legacy_prefix
#undef _
} x86_insn_parse_flag_bit_t;

typedef enum {
#define _(f, o) X86_INSN_##f = 1 << X86_INSN_FLAG_BIT_##f,
  foreach_x86_insn_parse_flag foreach_x86_legacy_prefix
#undef _
} x86_insn_parse_flag_t;

typedef struct {
  /* Registers in instruction.
     [0] is modrm reg field
     [1] is base reg
     [2] is index reg. */
  u8 regs[3];

  /* Scale for index register. */
  u8 log2_index_scale : 2;
  u8 log2_effective_operand_bytes : 3;
  u8 log2_effective_address_bytes : 3;

  i32 displacement;

  /* Parser flags: set of x86_insn_parse_flag_t enums. */
  u32 flags;

  i64 immediate;

  x86_insn_t insn;
} x86_insn_parse_t;

u8 *              x86_insn_parse(x86_insn_parse_t *p, u8 *code_start);
format_function_t format_x86_insn_parse;

#endif /* included_asm_x86_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
