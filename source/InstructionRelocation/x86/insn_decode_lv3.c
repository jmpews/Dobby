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
/* FIXME
   opcode name remove to save table space; enum
   x87
   3dnow
   cbw naming
*/

#include <vppinfra/error.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/asm_x86.h>

#define foreach_x86_gp_register _(AX) _(CX) _(DX) _(BX) _(SP) _(BP) _(SI) _(DI)

typedef enum {
#define _(r) X86_INSN_GP_REG_##r,
  foreach_x86_gp_register
#undef _
} x86_insn_gp_register_t;

typedef union {
  struct {
    u8 rm : 3;
    u8 reg : 3;
    u8 mode : 2;
  };
  u8 byte;
} x86_insn_modrm_byte_t;

typedef union {
  struct {
    u8 base : 3;
    u8 index : 3;
    u8 log2_scale : 2;
  };
  u8 byte;
} x86_insn_sib_byte_t;

always_inline uword x86_insn_has_modrm_byte(x86_insn_t *insn) {
  int i;
  for (i = 0; i < ARRAY_LEN(insn->operands); i++)
    switch (insn->operands[i].code) {
    case 'G':
    case 'E':
    case 'M':
    case 'R':
      return 1;
    }
  return 0;
}

always_inline uword x86_insn_immediate_type(x86_insn_t *insn) {
  int i;
  for (i = 0; i < ARRAY_LEN(insn->operands); i++)
    switch (insn->operands[i].code) {
    case 'J':
    case 'I':
    case 'O':
      return insn->operands[i].type;
    }
  return 0;
}

/* Opcode extension in modrm byte reg field. */
#define foreach_x86_insn_modrm_reg_group                                                                               \
  _(1) _(1a) _(2) _(3) _(4) _(5) _(6) _(7) _(8) _(9) _(10) _(11) _(12) _(13) _(14) _(15) _(16) _(p)

#define foreach_x86_insn_sse_group                                                                                     \
  _(10) _(28) _(50) _(58) _(60) _(68) _(70) _(78) _(c0) _(d0) _(d8) _(e0) _(e8) _(f0) _(f8)

enum {
#define _(x) X86_INSN_MODRM_REG_GROUP_##x,
  foreach_x86_insn_modrm_reg_group
#undef _
#define _(x) X86_INSN_SSE_GROUP_##x,
      foreach_x86_insn_sse_group
#undef _
};

enum {
#define _(x) X86_INSN_FLAG_MODRM_REG_GROUP_##x = X86_INSN_FLAG_SET_MODRM_REG_GROUP(1 + X86_INSN_MODRM_REG_GROUP_##x),
  foreach_x86_insn_modrm_reg_group
#undef _

#define _(x) X86_INSN_FLAG_SSE_GROUP_##x = X86_INSN_FLAG_SET_SSE_GROUP(1 + X86_INSN_SSE_GROUP_##x),
      foreach_x86_insn_sse_group
#undef _
};

#define foreach_x86_gp_reg _(AX) _(CX) _(DX) _(BX) _(SP) _(BP) _(SI) _(DI)

#define foreach_x86_condition                                                                                          \
  _(o) _(no) _(b) _(nb) _(z) _(nz) _(be) _(nbe) _(s) _(ns) _(p) _(np) _(l) _(nl) _(le) _(nle)

#define _3f(x, f, o0, o1, o2)                                                                                          \
  {                                                                                                                    \
    .name = #x, .flags = (f), .operands[0] = {.data = #o0}, .operands[1] = {.data = #o1},                              \
    .operands[2] = {.data = #o2},                                                                                      \
  }

#define _2f(x, f, o0, o1) _3f(x, f, o0, o1, __)
#define _1f(x, f, o0)     _2f(x, f, o0, __)
#define _0f(x, f)         _1f(x, f, __)

#define _3(x, o0, o1, o2) _3f(x, 0, o0, o1, o2)
#define _2(x, o0, o1)     _2f(x, 0, o0, o1)
#define _1(x, o0)         _1f(x, 0, o0)
#define _0(x)             _0f(x, 0)

static x86_insn_t x86_insns_one_byte[256] = {

#define _(x) _2(x, Eb, Gb), _2(x, Ev, Gv), _2(x, Gb, Eb), _2(x, Gv, Ev), _2(x, AL, Ib), _2(x, AX, Iz)

    /* 0x00 */
    _(add),
    _0(push_es),
    _0(pop_es),
    _(or),
    _0(push_cs),
    _0(escape_two_byte),

    /* 0x10 */
    _(adc),
    _0(push_ss),
    _0(pop_ss),
    _(sbb),
    _0(push_ds),
    _0(pop_ds),

    /* 0x20 */
    _(and),
    _0(segment_es),
    _0(daa),
    _(sub),
    _0(segment_cs),
    _0(das),

    /* 0x30 */
    _(xor),
    _0(segment_ss),
    _0(aaa),
    _(cmp),
    _0(segment_ds),
    _0(aas),

#undef _

/* 0x40 */
#define _(r) _1(inc, r),
    foreach_x86_gp_reg
#undef _
#define _(r) _1(dec, r),
        foreach_x86_gp_reg
#undef _

/* 0x50 */
#define _(r) _1f(push, X86_INSN_FLAG_DEFAULT_64_BIT, r),
            foreach_x86_gp_reg
#undef _
#define _(r) _1f(pop, X86_INSN_FLAG_DEFAULT_64_BIT, r),
                foreach_x86_gp_reg
#undef _

                    /* 0x60 */
                    _0(pusha),
    _0(popa),
    _2(bound, Gv, Ma),
    _2(movsxd, Gv, Ed),
    _0(segment_fs),
    _0(segment_gs),
    _0(operand_type),
    _0(address_size),
    _1f(push, X86_INSN_FLAG_DEFAULT_64_BIT, Iz),
    _3(imul, Gv, Ev, Iz),
    _1f(push, X86_INSN_FLAG_DEFAULT_64_BIT, Ib),
    _3(imul, Gv, Ev, Ib),
    _1(insb, DX),
    _1(insw, DX),
    _1(outsb, DX),
    _1(outsw, DX),

/* 0x70 */
#define _(x) _1(j##x, Jb),
    foreach_x86_condition
#undef _

        /* 0x80 */
        _2f(modrm_group_1, X86_INSN_FLAG_MODRM_REG_GROUP_1, Eb, Ib),
    _2f(modrm_group_1, X86_INSN_FLAG_MODRM_REG_GROUP_1, Ev, Iz),
    _2f(modrm_group_1, X86_INSN_FLAG_MODRM_REG_GROUP_1, Eb, Ib),
    _2f(modrm_group_1, X86_INSN_FLAG_MODRM_REG_GROUP_1, Ev, Ib),
    _2(test, Eb, Gb),
    _2(test, Ev, Gv),
    _2(xchg, Eb, Gb),
    _2(xchg, Ev, Gv),
    _2(mov, Eb, Gb),
    _2(mov, Ev, Gv),
    _2(mov, Gb, Eb),
    _2(mov, Gv, Ev),
    _2(mov, Ev, Sw),
    _2(lea, Gv, Ev),
    _2(mov, Sw, Ew),
    _1f(modrm_group_1a, X86_INSN_FLAG_MODRM_REG_GROUP_1a, Ev),

    /* 0x90 */
    _0(nop),
    _1(xchg, CX),
    _1(xchg, DX),
    _1(xchg, BX),
    _1(xchg, SP),
    _1(xchg, BP),
    _1(xchg, SI),
    _1(xchg, DI),
    _0(cbw),
    _0(cwd),
    _1(call, Ap),
    _0(wait),
    _0(pushf),
    _0(popf),
    _0(sahf),
    _0(lahf),

    /* 0xa0 */
    _2(mov, AL, Ob),
    _2(mov, AX, Ov),
    _2(mov, Ob, AL),
    _2(mov, Ov, AX),
    _0(movsb),
    _0(movsw),
    _0(cmpsb),
    _0(cmpsw),
    _2(test, AL, Ib),
    _2(test, AX, Iz),
    _1(stosb, AL),
    _1(stosw, AX),
    _1(lodsb, AL),
    _1(lodsw, AX),
    _1(scasb, AL),
    _1(scasw, AX),

    /* 0xb0 */
    _2(mov, AL, Ib),
    _2(mov, CL, Ib),
    _2(mov, DL, Ib),
    _2(mov, BL, Ib),
    _2(mov, AH, Ib),
    _2(mov, CH, Ib),
    _2(mov, DH, Ib),
    _2(mov, BH, Ib),
#define _(r) _2(mov, r, Iv),
    foreach_x86_gp_reg
#undef _

        /* 0xc0 */
        _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Eb, Ib),
    _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Ev, Ib),
    _1(ret, Iw),
    _0(ret),
    _2(les, Gz, Mp),
    _2(lds, Gz, Mp),
    _2f(modrm_group_11, X86_INSN_FLAG_MODRM_REG_GROUP_11, Eb, Ib),
    _2f(modrm_group_11, X86_INSN_FLAG_MODRM_REG_GROUP_11, Ev, Iz),
    _2(enter, Iw, Ib),
    _0(leave),
    _1(ret, Iw),
    _0(ret),
    _0(int3),
    _1(int, Ib),
    _0(into),
    _0(iret),

    /* 0xd0 */
    _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Eb, 1b),
    _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Ev, 1b),
    _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Eb, CL),
    _2f(modrm_group_2, X86_INSN_FLAG_MODRM_REG_GROUP_2, Ev, CL),
    _0(aam),
    _0(aad),
    _0(salc),
    _0(xlat),
    /* FIXME x87 */
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),

    /* 0xe0 */
    _1(loopnz, Jb),
    _1(loopz, Jb),
    _1(loop, Jb),
    _1(jcxz, Jb),
    _2(in, AL, Ib),
    _2(in, AX, Ib),
    _2(out, Ib, AL),
    _2(out, Ib, AX),
    _1f(call, X86_INSN_FLAG_DEFAULT_64_BIT, Jz),
    _1f(jmp, X86_INSN_FLAG_DEFAULT_64_BIT, Jz),
    _1(jmp, Ap),
    _1(jmp, Jb),
    _2(in, AL, DX),
    _2(in, AX, DX),
    _2(out, DX, AL),
    _2(out, DX, AX),

    /* 0xf0 */
    _0(lock),
    _0(int1),
    _0(repne),
    _0(rep),
    _0(hlt),
    _0(cmc),
    _0f(modrm_group_3, X86_INSN_FLAG_MODRM_REG_GROUP_3),
    _0f(modrm_group_3, X86_INSN_FLAG_MODRM_REG_GROUP_3),
    _0(clc),
    _0(stc),
    _0(cli),
    _0(sti),
    _0(cld),
    _0(std),
    _1f(modrm_group_4, X86_INSN_FLAG_MODRM_REG_GROUP_4, Eb),
    _0f(modrm_group_5, X86_INSN_FLAG_MODRM_REG_GROUP_5),
};

static x86_insn_t x86_insns_two_byte[256] = {
    /* 0x00 */
    _0f(modrm_group_6, X86_INSN_FLAG_MODRM_REG_GROUP_6),
    _0f(modrm_group_7, X86_INSN_FLAG_MODRM_REG_GROUP_7),
    _2(lar, Gv, Ew),
    _2(lsl, Gv, Ew),
    _0(bad),
    _0(syscall),
    _0(clts),
    _0(sysret),
    _0(invd),
    _0(wbinvd),
    _0(bad),
    _0(ud2),
    _0(bad),
    _0f(modrm_group_p, X86_INSN_FLAG_MODRM_REG_GROUP_p),
    _0(femms),
    _0(escape_3dnow),

    /* 0x10 */
    _2f(movups, X86_INSN_FLAG_SSE_GROUP_10, Gx, Ex),
    _2f(movups, X86_INSN_FLAG_SSE_GROUP_10, Ex, Gx),
    _2f(movlps, X86_INSN_FLAG_SSE_GROUP_10, Ex, Gx),
    _2f(movlps, X86_INSN_FLAG_SSE_GROUP_10, Gx, Ex),
    _2f(unpcklps, X86_INSN_FLAG_SSE_GROUP_10, Gx, Ex),
    _2f(unpckhps, X86_INSN_FLAG_SSE_GROUP_10, Gx, Ex),
    _2f(movhps, X86_INSN_FLAG_SSE_GROUP_10, Ex, Gx),
    _2f(movhps, X86_INSN_FLAG_SSE_GROUP_10, Gx, Ex),
    _0f(modrm_group_16, X86_INSN_FLAG_MODRM_REG_GROUP_16),
    _0(nop),
    _0(nop),
    _0(nop),
    _0(nop),
    _0(nop),
    _0(nop),
    _0(nop),

    /* 0x20 */
    _2(mov, Rv, Cv),
    _2(mov, Rv, Dv),
    _2(mov, Cv, Rv),
    _2(mov, Dv, Rv),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _2f(movaps, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),
    _2f(movaps, X86_INSN_FLAG_SSE_GROUP_28, Ex, Gx),
    _2f(cvtpi2ps, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),
    _2f(movntps, X86_INSN_FLAG_SSE_GROUP_28, Mx, Gx),
    _2f(cvttps2pi, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),
    _2f(cvtps2pi, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),
    _2f(ucomiss, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),
    _2f(comiss, X86_INSN_FLAG_SSE_GROUP_28, Gx, Ex),

    /* 0x30 */
    _0(wrmsr),
    _0(rdtsc),
    _0(rdmsr),
    _0(rdpmc),
    _0(sysenter),
    _0(sysexit),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),
    _0(bad),

/* 0x40 */
#define _(x) _2(cmov##x, Gv, Ev),
    foreach_x86_condition
#undef _

        /* 0x50 */
        _2f(movmskps, X86_INSN_FLAG_SSE_GROUP_50, Gd, Rx),
    _2f(sqrtps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(rsqrtps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(rcpps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(andps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(andnps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(orps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(xorps, X86_INSN_FLAG_SSE_GROUP_50, Gx, Ex),
    _2f(addps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(mulps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(cvtps2pd, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(cvtdq2ps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(subps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(minps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(divps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),
    _2f(maxps, X86_INSN_FLAG_SSE_GROUP_58, Gx, Ex),

    /* 0x60 */
    _2f(punpcklbw, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(punpcklwd, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(punpckldq, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(packsswb, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(pcmpgtb, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(pcmpgtw, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(pcmpgtd, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(packuswb, X86_INSN_FLAG_SSE_GROUP_60, Gm, Em),
    _2f(punpckhbw, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),
    _2f(punpckhwd, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),
    _2f(punpckhdq, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),
    _2f(packssdw, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_68),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_68),
    _2f(movd, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),
    _2f(movq, X86_INSN_FLAG_SSE_GROUP_68, Gm, Em),

    /* 0x70 */
    _3f(pshufw, X86_INSN_FLAG_SSE_GROUP_70, Gm, Em, Ib),
    _0f(modrm_group_12, X86_INSN_FLAG_MODRM_REG_GROUP_12),
    _0f(modrm_group_13, X86_INSN_FLAG_MODRM_REG_GROUP_13),
    _0f(modrm_group_14, X86_INSN_FLAG_MODRM_REG_GROUP_14),
    _2f(pcmpeqb, X86_INSN_FLAG_SSE_GROUP_70, Gm, Em),
    _2f(pcmpeqw, X86_INSN_FLAG_SSE_GROUP_70, Gm, Em),
    _2f(pcmpeqd, X86_INSN_FLAG_SSE_GROUP_70, Gm, Em),
    _0f(emms, X86_INSN_FLAG_SSE_GROUP_70),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_78),
    _2f(movd, X86_INSN_FLAG_SSE_GROUP_78, Em, Gm),
    _2f(movq, X86_INSN_FLAG_SSE_GROUP_78, Em, Gm),

/* 0x80 */
#define _(x) _1(jmp##x, Jz),
    foreach_x86_condition
#undef _

/* 0x90 */
#define _(x) _1(set##x, Eb),
        foreach_x86_condition
#undef _

            /* 0xa0 */
            _0(push_fs),
    _0(pop_fs),
    _0(cpuid),
    _2(bt, Ev, Gv),
    _3(shld, Ev, Gv, Ib),
    _3(shld, Ev, Gv, CL),
    _0(bad),
    _0(bad),
    _0(push_gs),
    _0(pop_gs),
    _0(rsm),
    _2(bts, Ev, Gv),
    _3(shrd, Ev, Gv, Ib),
    _3(shrd, Ev, Gv, CL),
    _0f(modrm_group_15, X86_INSN_FLAG_MODRM_REG_GROUP_15),
    _2(imul, Gv, Ev),

    /* 0xb0 */
    _2(cmpxchg, Eb, Gb),
    _2(cmpxchg, Ev, Gv),
    _2(lss, Gz, Mp),
    _2(btr, Ev, Gv),
    _2(lfs, Gz, Mp),
    _2(lgs, Gz, Mp),
    _2(movzbl, Gv, Eb),
    _2(movzwl, Gv, Ew),
    _0(bad),
    _0f(modrm_group_10, X86_INSN_FLAG_MODRM_REG_GROUP_10),
    _2f(modrm_group_8, X86_INSN_FLAG_MODRM_REG_GROUP_8, Ev, Ib),
    _2(btc, Ev, Gv),
    _2(bsf, Gv, Ev),
    _2(bsr, Gv, Ev),
    _2(movsx, Gv, Eb),
    _2(movsx, Gv, Ew),

    /* 0xc0 */
    _2(xadd, Eb, Gb),
    _2(xadd, Ev, Gv),
    _3f(cmpps, X86_INSN_FLAG_SSE_GROUP_c0, Gx, Ex, Ib),
    _2(movnti, Mv, Gv),
    _3f(pinsrw, X86_INSN_FLAG_SSE_GROUP_c0, Gm, Ew, Ib),
    _3f(pextrw, X86_INSN_FLAG_SSE_GROUP_c0, Gd, Rm, Ib),
    _3f(shufps, X86_INSN_FLAG_SSE_GROUP_c0, Gx, Ex, Ib),
    _1f(modrm_group_9, X86_INSN_FLAG_MODRM_REG_GROUP_9, Mx),
#define _(r) _1(bswap, r),
    foreach_x86_gp_reg
#undef _

        /* 0xd0 */
        _0f(bad, X86_INSN_FLAG_SSE_GROUP_d0),
    _2f(psrlw, X86_INSN_FLAG_SSE_GROUP_d0, Gm, Em),
    _2f(psrld, X86_INSN_FLAG_SSE_GROUP_d0, Gm, Em),
    _2f(psrlq, X86_INSN_FLAG_SSE_GROUP_d0, Gm, Em),
    _2f(paddq, X86_INSN_FLAG_SSE_GROUP_d0, Gm, Em),
    _2f(pmullw, X86_INSN_FLAG_SSE_GROUP_d0, Gm, Em),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_d0),
    _2f(pmovmskb, X86_INSN_FLAG_SSE_GROUP_d0, Gd, Rm),
    _2f(psubusb, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(psubusw, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(pminub, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(pand, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(paddusb, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(paddusw, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(pmaxub, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),
    _2f(pandn, X86_INSN_FLAG_SSE_GROUP_d8, Gm, Em),

    /* 0xe0 */
    _2f(pavgb, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(psraw, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(psrad, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(pavgw, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(pmulhuw, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(pmulhw, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(bad, X86_INSN_FLAG_SSE_GROUP_e0, Gm, Em),
    _2f(movntq, X86_INSN_FLAG_SSE_GROUP_e0, Mm, Gm),
    _2f(psubsb, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(psubsw, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(pminsw, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(por, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(paddsb, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(paddsw, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(pmaxsw, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),
    _2f(pxor, X86_INSN_FLAG_SSE_GROUP_e8, Gm, Em),

    /* 0xf0 */
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_f0),
    _2f(psllw, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(pslld, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(psllq, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(pmuludq, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(pmaddwd, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(psadbw, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(maskmovq, X86_INSN_FLAG_SSE_GROUP_f0, Gm, Em),
    _2f(psubb, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(psubw, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(psubd, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(psubq, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(paddb, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(paddw, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _2f(paddd, X86_INSN_FLAG_SSE_GROUP_f8, Gm, Em),
    _0f(bad, X86_INSN_FLAG_SSE_GROUP_f8),
};

typedef struct {
  x86_insn_t insns[8];
} x86_insn_group8_t;

/* Escape groups are indexed by modrm reg field. */
static x86_insn_group8_t x86_insn_modrm_reg_groups[] = {
    [X86_INSN_MODRM_REG_GROUP_1].insns =
        {
            _0(add),
            _0(or),
            _0(adc),
            _0(sbb),
            _0(and),
            _0(sub),
            _0(xor),
            _0(cmp),
        },

    [X86_INSN_MODRM_REG_GROUP_1a].insns =
        {
            _0f(pop, X86_INSN_FLAG_DEFAULT_64_BIT),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_2].insns =
        {
            _0(rol),
            _0(ror),
            _0(rcl),
            _0(rcr),
            _0(shl),
            _0(shr),
            _0(sal),
            _0(sar),
        },

    [X86_INSN_MODRM_REG_GROUP_3].insns =
        {
            _0(test),
            _0(test),
            _0(not ),
            _0(neg),
            _0(mul),
            _0(imul),
            _0(div),
            _0(idiv),
        },

    [X86_INSN_MODRM_REG_GROUP_4].insns =
        {
            _0(inc),
            _0(dec),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_5].insns =
        {
            _1(inc, Ev),
            _1(dec, Ev),
            _1f(call, X86_INSN_FLAG_DEFAULT_64_BIT, Ev),
            _1(call, Mp),
            _1f(jmp, X86_INSN_FLAG_DEFAULT_64_BIT, Ev),
            _1(jmp, Mp),
            _1f(push, X86_INSN_FLAG_DEFAULT_64_BIT, Ev),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_6].insns =
        {
            _1(sldt, Ev),
            _1(str, Ev),
            _1(lldt, Ev),
            _1(ltr, Ev),
            _1(verr, Ev),
            _1(verw, Ev),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_7].insns =
        {
            _1(sgdt, Mv),
            _1(sidt, Mv),
            _1(lgdt, Mv),
            _1(lidt, Mv),
            _1(smsw, Ev),
            _0(bad),
            _1(lmsw, Ew),
            _1(invlpg, Mv),
        },

    [X86_INSN_MODRM_REG_GROUP_8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(bt, Ev, Ib),
            _2(bts, Ev, Ib),
            _2(btr, Ev, Ib),
            _2(btc, Ev, Ib),
        },

    [X86_INSN_MODRM_REG_GROUP_9].insns =
        {
            _0(bad),
            _1(cmpxchg, Mx),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_10].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_11].insns =
        {
            _0(mov),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_12].insns =
        {
            _0(bad),
            _0(bad),
            _2(psrlw, Rm, Ib),
            _0(bad),
            _2(psraw, Rm, Ib),
            _0(bad),
            _2(psllw, Rm, Ib),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_13].insns =
        {
            _0(bad),
            _0(bad),
            _2(psrld, Rm, Ib),
            _0(bad),
            _2(psrad, Rm, Ib),
            _0(bad),
            _2(pslld, Rm, Ib),
            _0(bad),
        },

    [X86_INSN_MODRM_REG_GROUP_14].insns =
        {
            _0(bad),
            _0(bad),
            _2(psrlq, Rm, Ib),
            _0f(bad, 0),
            _0(bad),
            _0(bad),
            _2(psllq, Rm, Ib),
            _0f(bad, 0),
        },

    [X86_INSN_MODRM_REG_GROUP_15].insns =
        {
            _1(fxsave, Mv),
            _1(fxrstor, Mv),
            _1(ldmxcsr, Mv),
            _1(stmxcsr, Mv),
            _0(bad),
            _1(lfence, Mv),
            _1(mfence, Mv),
            _1(sfence, Mv),
        },

    [X86_INSN_MODRM_REG_GROUP_16].insns =
        {
            _1(prefetch_nta, Mv),
            _1(prefetch_t0, Mv),
            _1(prefetch_t1, Mv),
            _1(prefetch_t2, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
        },

    [X86_INSN_MODRM_REG_GROUP_p].insns =
        {
            _1(prefetch_exclusive, Mv),
            _1(prefetch_modified, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_modified, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
            _1(prefetch_nop, Mv),
        },
};

static x86_insn_group8_t x86_insn_sse_groups_repz[] = {
    [X86_INSN_SSE_GROUP_10].insns =
        {
            _2(movss, Gx, Ex),
            _2(movss, Ex, Gx),
            _2(movsldup, Gx, Ex),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(movshdup, Gx, Ex),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_28].insns =
        {
            _0(bad),
            _0(bad),
            _2(cvtsi2ss, Gx, Ev),
            _0(bad),
            _2(cvttss2si, Gv, Ex),
            _2(cvtss2si, Gv, Ex),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_50].insns =
        {
            _0(bad),
            _2(sqrtss, Gx, Ex),
            _2(rsqrtps, Gx, Ex),
            _2(rcpss, Gx, Ex),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_58].insns =
        {
            _2(addss, Gx, Ex),
            _2(mulss, Gx, Ex),
            _2(cvtss2sd, Gx, Ex),
            _2(cvttps2dq, Gx, Ex),
            _2(subss, Gx, Ex),
            _2(minss, Gx, Ex),
            _2(divss, Gx, Ex),
            _2(maxss, Gx, Ex),
        },

    [X86_INSN_SSE_GROUP_60].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_68].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(movdqu, Gx, Ex),
        },

    [X86_INSN_SSE_GROUP_70].insns =
        {
            _3(pshufhw, Gx, Ex, Ib),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_78].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(movq, Gx, Ex),
            _2(movdqu, Ex, Gx),
        },

    [X86_INSN_SSE_GROUP_c0].insns =
        {
            _0(bad),
            _0(bad),
            _3(cmpss, Gx, Ex, Ib),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_d0].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(movq2dq, Gx, Em),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_d8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_e0].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(cvtdq2pd, Gx, Ex),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_e8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_f0].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_f8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },
};

static x86_insn_group8_t x86_insn_sse_groups_operand_size[] =
    {
        [X86_INSN_SSE_GROUP_10].insns =
            {
                _2(movupd, Gx, Ex),
                _2(movupd, Ex, Gx),
                _2(movlpd, Gx, Ex),
                _2(movlpd, Ex, Gx),
                _2(unpcklpd, Gx, Ex),
                _2(unpckhpd, Gx, Ex),
                _2(movhpd, Gx, Mx),
                _2(movhpd, Mx, Gx),
            },

        [X86_INSN_SSE_GROUP_28].insns =
            {
                _2(movapd, Gx, Ex),
                _2(movapd, Ex, Gx),
                _2(cvtpi2pd, Gx, Ex),
                _2(movntpd, Mx, Gx),
                _2(cvttpd2pi, Gx, Mx),
                _2(cvtpd2pi, Gx, Mx),
                _2(ucomisd, Gx, Ex),
                _2(comisd, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_50].insns =
            {
                _2(movmskpd, Gd, Rx),
                _2(sqrtpd, Gx, Ex),
                _0(bad),
                _0(bad),
                _2(andpd, Gx, Ex),
                _2(andnpd, Gx, Ex),
                _2(orpd, Gx, Ex),
                _2(xorpd, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_58].insns =
            {
                _2(addpd, Gx, Ex),
                _2(mulpd, Gx, Ex),
                _2(cvtpd2ps, Gx, Ex),
                _2(cvtps2dq, Gx, Ex),
                _2(subpd, Gx, Ex),
                _2(minpd, Gx, Ex),
                _2(divpd, Gx, Ex),
                _2(maxpd, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_60].insns =
            {
                _2(punpcklbw, Gx, Ex),
                _2(punpcklwd, Gx, Ex),
                _2(punpckldq, Gx, Ex),
                _2(packsswb, Gx, Ex),
                _2(pcmpgtb, Gx, Ex),
                _2(pcmpgtw, Gx, Ex),
                _2(pcmpgtd, Gx, Ex),
                _2(packuswb, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_68].insns =
            {
                _2(punpckhbw, Gx, Ex),
                _2(punpckhwd, Gx, Ex),
                _2(punpckhdq, Gx, Ex),
                _2(packssdw, Gx, Ex),
                _2(punpcklqdq, Gx, Ex),
                _2(punpckhqdq, Gx, Ex),
                _2(movd, Gx, Ev),
                _2(movdqa, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_70].insns =
            {
                _3(pshufd, Gx, Ex, Ib),
                _0f(modrm_group_12, X86_INSN_FLAG_MODRM_REG_GROUP_12),
                _0f(modrm_group_13, X86_INSN_FLAG_MODRM_REG_GROUP_13),
                _0f(modrm_group_14, X86_INSN_FLAG_MODRM_REG_GROUP_14),
                _2(pcmpeqb, Gx, Ex),
                _2(pcmpeqw, Gx, Ex),
                _2(pcmpeqd, Gx, Ex),
                _0(bad),
            },

        [X86_INSN_SSE_GROUP_78].insns =
            {
                _0(bad),
                _0(bad),
                _0(bad),
                _0(bad),
                _2(haddpd, Gx, Ex),
                _2(hsubpd, Gx, Ex),
                _2(movd, Ev, Gx),
                _2(movdqa, Ex, Gx),
            },

        [X86_INSN_SSE_GROUP_c0].insns =
            {
                _0(bad),
                _0(bad),
                _3(cmppd, Gx, Ex, Ib),
                _0(bad),
                _3(pinsrw, Gx, Ew, Ib),
                _3(pextrw, Gd, Gx, Ib),
                _3(shufpd, Gx, Ex, Ib),
                _0(bad),
            },

        [X86_INSN_SSE_GROUP_d0].insns =
            {
                _2(addsubpd, Gx, Ex),
                _2(psrlw, Gx, Ex),
                _2(psrld, Gx, Ex),
                _2(psrlq, Gx, Ex),
                _2(paddq, Gx, Ex),
                _2(pmullw, Gx, Ex),
                _2(movq, Ex, Gx),
                _2(pmovmskb, Gd, Rx),
            },

        [X86_INSN_SSE_GROUP_d8].insns =
            {
                _2(psubusb, Gx, Ex),
                _2(psubusw, Gx, Ex),
                _2(pminub, Gx, Ex),
                _2(pand, Gx, Ex),
                _2(paddusb, Gx, Ex),
                _2(paddusw, Gx, Ex),
                _2(pmaxub, Gx, Ex),
                _2(pandn, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_e0].insns =
            {
                _2(pavgb, Gx, Ex),
                _2(psraw, Gx, Ex),
                _2(psrad, Gx, Ex),
                _2(pavgw, Gx, Ex),
                _2(pmulhuw, Gx, Ex),
                _2(pmulhw, Gx, Ex),
                _2(cvttpd2dq, Gx, Ex),
                _2(movntdq, Mx, Gx),
            },

        [X86_INSN_SSE_GROUP_e8].insns =
            {
                _2(psubsb, Gx, Ex),
                _2(psubsw, Gx, Ex),
                _2(pminsw, Gx, Ex),
                _2(por, Gx, Ex),
                _2(paddsb, Gx, Ex),
                _2(paddsw, Gx, Ex),
                _2(pmaxsw, Gx, Ex),
                _2(pxor, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_f0].insns =
            {
                _0(bad),
                _2(psllw, Gx, Ex),
                _2(pslld, Gx, Ex),
                _2(psllq, Gx, Ex),
                _2(pmuludq, Gx, Ex),
                _2(pmaddwd, Gx, Ex),
                _2(psadbw, Gx, Ex),
                _2(maskmovdqu, Gx, Ex),
            },

        [X86_INSN_SSE_GROUP_f8].insns =
            {
                _2(psubb, Gx, Ex),
                _2(psubw, Gx, Ex),
                _2(psubd, Gx, Ex),
                _2(psubq, Gx, Ex),
                _2(paddb, Gx, Ex),
                _2(paddw, Gx, Ex),
                _2(paddd, Gx, Ex),
                _0(bad),
            },
};

static x86_insn_group8_t x86_insn_sse_groups_repnz[] = {
    [X86_INSN_SSE_GROUP_10].insns =
        {
            _2(movsd, Gx, Ex),
            _2(movsd, Ex, Gx),
            _2(movddup, Gx, Ex),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_28].insns =
        {
            _0(bad),
            _0(bad),
            _2(cvtsi2sd, Gx, Ev),
            _0(bad),
            _2(cvttsd2si, Gv, Ex),
            _2(cvtsd2si, Gv, Ex),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_50].insns =
        {
            _0(bad),
            _2(sqrtsd, Gx, Ex),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_58].insns =
        {
            _2(addsd, Gx, Ex),
            _2(mulsd, Gx, Ex),
            _2(cvtsd2ss, Gx, Ex),
            _0(bad),
            _2(subsd, Gx, Ex),
            _2(minsd, Gx, Ex),
            _2(divsd, Gx, Ex),
            _2(maxsd, Gx, Ex),
        },

    [X86_INSN_SSE_GROUP_60].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_68].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_70].insns =
        {
            _3(pshuflw, Gx, Ex, Ib),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_78].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(haddps, Gx, Ex),
            _2(hsubps, Gx, Ex),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_c0].insns =
        {
            _0(bad),
            _0(bad),
            _3(cmpsd, Gx, Ex, Ib),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_d0].insns =
        {
            _2(addsubps, Gx, Ex),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(movdq2q, Gm, Ex),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_d8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_e0].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _2(cvtpd2dq, Gx, Ex),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_e8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_f0].insns =
        {
            _2(lddqu, Gx, Mx),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },

    [X86_INSN_SSE_GROUP_f8].insns =
        {
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
            _0(bad),
        },
};

#undef _

/* Parses memory displacements and immediates. */
static u8 *x86_insn_parse_number(u32 log2_n_bytes, u8 *code, u8 *code_end, i64 *result) {
  i64 x = 0;

  if (code + (1 << log2_n_bytes) > code_end)
    return 0;

  switch (log2_n_bytes) {
  case 3:
    x = clib_little_to_host_unaligned_mem_u64((u64 *)code);
    break;

  case 2:
    x = (i32)clib_little_to_host_unaligned_mem_u32((u32 *)code);
    break;

  case 1:
    x = (i16)clib_little_to_host_unaligned_mem_u16((u16 *)code);
    break;

  case 0:
    x = (i8)code[0];
    break;

  default:
    ASSERT(0);
  }

  *result = x;
  return code + (1 << log2_n_bytes);
}

static u32 x86_insn_log2_immediate_bytes(x86_insn_parse_t *p, x86_insn_t *insn) {
  u32 i = ~0;
  switch (x86_insn_immediate_type(insn)) {
  case 'b':
    i = 0;
    break;
  case 'w':
    i = 1;
    break;
  case 'd':
    i = 2;
    break;
  case 'q':
    i = 3;
    break;

  case 'z':
    i = p->log2_effective_operand_bytes;
    if (i > 2)
      i = 2;
    break;

  case 'v':
    i = p->log2_effective_operand_bytes;
    break;

  default:
    i = ~0;
    break;
  }

  return i;
}

static u8 *x86_insn_parse_modrm_byte(x86_insn_parse_t *x, x86_insn_modrm_byte_t modrm, u32 parse_flags, u8 *code,
                                     u8 *code_end) {
  u8 effective_address_bits;

  if (parse_flags & X86_INSN_PARSE_64_BIT)
    effective_address_bits = (x->flags & X86_INSN_ADDRESS_SIZE) ? 32 : 64;
  else if (parse_flags & X86_INSN_PARSE_32_BIT)
    effective_address_bits = (x->flags & X86_INSN_ADDRESS_SIZE) ? 16 : 32;
  else
    effective_address_bits = (x->flags & X86_INSN_ADDRESS_SIZE) ? 32 : 16;

  x->log2_effective_address_bytes = 1;
  x->log2_effective_address_bytes += effective_address_bits > 16;
  x->log2_effective_address_bytes += effective_address_bits > 32;

  x->regs[0] |= modrm.reg;
  if (modrm.mode == 3)
    x->regs[1] |= modrm.rm;
  else {
    u32 log2_disp_bytes = ~0;

    x->flags |= X86_INSN_IS_ADDRESS;

    if (effective_address_bits != 16) {
      u8 has_sib_byte = 0;

      switch (modrm.mode) {
      case 0:
        /* When base is bp displacement is present for mode 0. */
        if (modrm.rm == X86_INSN_GP_REG_BP) {
          log2_disp_bytes = x->log2_effective_address_bytes;
          break;
        } else if (modrm.rm == X86_INSN_GP_REG_SP && effective_address_bits != 16) {
          has_sib_byte = 1;
          break;
        }
        /* fall through */
      case 1:
      case 2:
        x->regs[1] |= modrm.rm;
        x->flags |= X86_INSN_HAS_BASE;
        if (modrm.mode != 0) {
          log2_disp_bytes = (modrm.mode == 1 ? 0 : x->log2_effective_address_bytes);
          if (log2_disp_bytes > 2)
            log2_disp_bytes = 2;
        }
        break;
      }

      if (has_sib_byte) {
        x86_insn_sib_byte_t sib;

        if (code >= code_end)
          return 0;
        sib.byte = *code++;

        x->log2_index_scale = 1 << sib.log2_scale;
        x->regs[1] |= sib.base;
        x->flags |= X86_INSN_HAS_BASE;

        if (sib.index != X86_INSN_GP_REG_SP) {
          x->regs[2] |= sib.index;
          x->flags |= X86_INSN_HAS_INDEX;
        }
      }
    } else {
      /* effective_address_bits == 16 */
      switch (modrm.mode) {
      case 0:
        if (modrm.rm == 6) {
          /* [disp16] */
          log2_disp_bytes = 1;
          break;
        }
        /* fall through */
      case 1:
      case 2:
        switch (modrm.rm) {
        case 0: /* [bx + si/di] */
        case 1:
          x->regs[1] = X86_INSN_GP_REG_BX;
          x->regs[2] = X86_INSN_GP_REG_SI + (modrm.rm & 1);
          x->flags |= X86_INSN_HAS_BASE | X86_INSN_HAS_INDEX;
          break;

        case 2: /* [bp + si/di] */
        case 3:
          x->regs[1] = X86_INSN_GP_REG_BP;
          x->regs[2] = X86_INSN_GP_REG_SI + (modrm.rm & 1);
          x->flags |= X86_INSN_HAS_BASE | X86_INSN_HAS_INDEX;
          break;

        case 4: /* [si/di] */
        case 5:
          x->regs[1] = X86_INSN_GP_REG_SI + (modrm.rm & 1);
          x->flags |= X86_INSN_HAS_BASE;
          break;

        case 6: /* [bp + disp] */
          x->regs[1] = X86_INSN_GP_REG_BP;
          x->flags |= X86_INSN_HAS_BASE;
          break;

        case 7: /* [bx + disp] */
          x->regs[1] = X86_INSN_GP_REG_BX;
          x->flags |= X86_INSN_HAS_BASE;
          break;
        }

        if (modrm.mode != 0)
          log2_disp_bytes = modrm.mode == 1 ? 0 : 1;
        break;
      }
    }

    if (log2_disp_bytes != ~0) {
      i64 disp;
      code = x86_insn_parse_number(log2_disp_bytes, code, code_end, &disp);
      if (code)
        x->displacement = disp;
    }
  }

  return code;
}

u8 *x86_insn_parse(x86_insn_parse_t *p, u8 *code_start) {
  u8          i, *code, *code_end;
  x86_insn_t *insn, *group_insn;
  u8          default_operand_bits, effective_operand_bits;
  u32         opcode, parse_flags;

  /* Preserve global parse flags. */
  parse_flags = p->flags & (X86_INSN_PARSE_32_BIT | X86_INSN_PARSE_64_BIT);
  clib_memset(p, 0, sizeof(p[0]));
  p->flags = parse_flags;

  /* 64 implies 32 bit parsing. */
  if (parse_flags & X86_INSN_PARSE_64_BIT)
    parse_flags |= X86_INSN_PARSE_32_BIT;

  /* Instruction must be <= 15 bytes. */
  code     = code_start;
  code_end = code + 15;

  /* Parse legacy prefixes. */
  while (1) {
    if (code >= code_end)
      goto insn_too_long;
    i = code[0];
    code++;
    switch (i) {
    default:
      goto prefix_done;

      /* Set flags based on prefix. */
#define _(x, o)                                                                                                        \
  case o:                                                                                                              \
    p->flags |= X86_INSN_##x;                                                                                          \
    break;
      foreach_x86_legacy_prefix;
#undef _
    }
  }
prefix_done:

  /* REX prefix. */
  if ((parse_flags & X86_INSN_PARSE_64_BIT) && i >= 0x40 && i <= 0x4f) {
    p->regs[0] |= ((i & (1 << 2)) != 0) << 3; /* r bit */
    p->regs[1] |= ((i & (1 << 0)) != 0) << 3; /* b bit */
    p->regs[2] |= ((i & (1 << 1)) != 0) << 3; /* x bit */
    p->flags |= ((i & (1 << 3))               /* w bit */
                     ? X86_INSN_OPERAND_SIZE_64
                     : 0);
    if (code >= code_end)
      goto insn_too_long;
    i = *code++;
  }

  opcode = i;
  if (opcode == 0x0f) {
    /* two byte opcode. */;
    if (code >= code_end)
      goto insn_too_long;
    i      = *code++;
    opcode = (opcode << 8) | i;
    insn   = x86_insns_two_byte + i;
  } else {
    static x86_insn_t arpl = {
        .name             = "arpl",
        .operands[0].data = "Ew",
        .operands[1].data = "Gw",
    };

    if (PREDICT_FALSE(i == 0x63 && !(parse_flags & X86_INSN_PARSE_64_BIT)))
      insn = &arpl;
    else
      insn = x86_insns_one_byte + i;
  }

  if ((i = X86_INSN_FLAG_GET_SSE_GROUP(insn->flags)) != 0) {
    x86_insn_group8_t *g8;

    if (p->flags & X86_INSN_OPERAND_SIZE)
      g8 = x86_insn_sse_groups_operand_size;
    else if (p->flags & X86_INSN_REPZ)
      g8 = x86_insn_sse_groups_repz;
    else if (p->flags & X86_INSN_REPNZ)
      g8 = x86_insn_sse_groups_repnz;
    else
      g8 = 0;

    /* insn flags have 1 + group so != 0 test above can work. */
    ASSERT((i - 1) < ARRAY_LEN(x86_insn_sse_groups_operand_size));
    if (g8)
      insn = g8[i - 1].insns + (opcode & 7);
  }

  /* Parse modrm and displacement if present. */
  if (x86_insn_has_modrm_byte(insn)) {
    x86_insn_modrm_byte_t modrm;

    if (code >= code_end)
      goto insn_too_long;
    modrm.byte = *code++;

    /* Handle special 0x0f01 and 0x0fae encodings. */
    if (PREDICT_FALSE(modrm.mode == 3 && (opcode == 0x0f01 || opcode == 0x0fae))) {
      static x86_insn_t x86_insns_0f01_special[] = {
          _0(swapgs), _0(rdtscp), _0(bad), _0(bad), _0(bad), _0(bad), _0(bad), _0(bad),
      };
      static x86_insn_t x86_insns_0fae_special[] = {
          _0(vmrun), _0(vmmcall), _0(vmload), _0(vmsave), _0(stgi), _0(clgi), _0(skinit), _0(invlpga),
      };

      if (opcode == 0x0f01)
        insn = x86_insns_0f01_special;
      else
        insn = x86_insns_0fae_special;
      insn += modrm.rm;
      opcode = (opcode << 8) | modrm.byte;
    } else {
      code = x86_insn_parse_modrm_byte(p, modrm, parse_flags, code, code_end);
      if (!code)
        goto insn_too_long;
    }
  }

  group_insn = 0;
  if ((i = X86_INSN_FLAG_GET_MODRM_REG_GROUP(insn->flags)) != 0) {
    u32 g = i - 1;
    ASSERT(g < ARRAY_LEN(x86_insn_modrm_reg_groups));
    group_insn = x86_insn_modrm_reg_groups[g].insns + (p->regs[0] & 7);
  }

  p->insn = insn[0];
  if (group_insn) {
    u32 k;
    p->insn.name = group_insn->name;
    p->insn.flags |= group_insn->flags;
    for (k = 0; k < ARRAY_LEN(group_insn->operands); k++)
      if (x86_insn_operand_is_valid(group_insn, k))
        p->insn.operands[k] = group_insn->operands[k];
  }

  default_operand_bits =
      ((((parse_flags & X86_INSN_PARSE_32_BIT) != 0) ^ ((p->flags & X86_INSN_OPERAND_SIZE) != 0)) ? BITS(u32)
                                                                                                  : BITS(u16));

  if ((parse_flags & X86_INSN_PARSE_64_BIT) && (p->insn.flags & X86_INSN_FLAG_DEFAULT_64_BIT))
    default_operand_bits = BITS(u64);

  effective_operand_bits = default_operand_bits;
  if (p->flags & X86_INSN_OPERAND_SIZE_64)
    effective_operand_bits = BITS(u64);

  p->log2_effective_operand_bytes = 1;
  p->log2_effective_operand_bytes += effective_operand_bits > 16;
  p->log2_effective_operand_bytes += effective_operand_bits > 32;

  /* Parse immediate if present. */
  {
    u32 l = x86_insn_log2_immediate_bytes(p, insn);
    if (l <= 3) {
      code = x86_insn_parse_number(l, code, code_end, &p->immediate);
      if (!code)
        goto insn_too_long;
    }
  }

  return code;

insn_too_long:
  return 0;
}

static u8 *format_x86_gp_reg_operand(u8 *s, va_list *va) {
  u32 r            = va_arg(*va, u32);
  u32 log2_n_bytes = va_arg(*va, u32);

  const char names8[8]  = "acdbsbsd";
  const char names16[8] = "xxxxppii";

  ASSERT(r < 16);

  /* Add % register prefix. */
  vec_add1(s, '%');

  switch (log2_n_bytes) {
  case 0: {

    if (r < 8)
      s = format(s, "%c%c", names8[r & 3], (r >> 2) ? 'l' : 'h');
    else
      s = format(s, "r%db", r);
  } break;

  case 2:
  case 3:
    s = format(s, "%c", log2_n_bytes == 2 ? 'e' : 'r');
    /* fall through */
  case 1:
    if (r < 8)
      s = format(s, "%c%c", names8[r], names16[r]);
    else {
      s = format(s, "%d", r);
      if (log2_n_bytes != 3)
        s = format(s, "%c", log2_n_bytes == 1 ? 'w' : 'd');
    }
    break;

  default:
    ASSERT(0);
  }

  return s;
}

static u8 *format_x86_reg_operand(u8 *s, va_list *va) {
  u32 reg          = va_arg(*va, u32);
  u32 log2_n_bytes = va_arg(*va, u32);
  u32 type         = va_arg(*va, u32);

  switch (type) {
  default:
    ASSERT(0);
    break;

  case 'x':
    ASSERT(reg < 16);
    return format(s, "%%xmm%d", reg);

  case 'm':
    ASSERT(reg < 8);
    return format(s, "%%mm%d", reg);

    /* Explicit byte/word/double-word/quad-word */
  case 'b':
    log2_n_bytes = 0;
    break;
  case 'w':
    log2_n_bytes = 1;
    break;
  case 'd':
    log2_n_bytes = 2;
    break;
  case 'q':
    log2_n_bytes = 3;
    break;

    /* Use effective operand size. */
  case 'v':
    break;

    /* word or double-word depending on effective operand size. */
  case 'z':
    log2_n_bytes = clib_min(log2_n_bytes, 2);
    break;
  }

  s = format(s, "%U", format_x86_gp_reg_operand, reg, log2_n_bytes);
  return s;
}

static u8 *format_x86_mem_operand(u8 *s, va_list *va) {
  x86_insn_parse_t *p = va_arg(*va, x86_insn_parse_t *);

  if (p->displacement != 0)
    s = format(s, "0x%x", p->displacement);

  if (p->flags & X86_INSN_HAS_BASE) {
    s = format(s, "(%U", format_x86_gp_reg_operand, p->regs[1], p->log2_effective_address_bytes);
    if (p->flags & X86_INSN_HAS_INDEX) {
      s = format(s, ",%U", format_x86_gp_reg_operand, p->regs[2], p->log2_effective_address_bytes);
      if (p->log2_index_scale != 0)
        s = format(s, ",%d", 1 << p->log2_index_scale);
    }
    s = format(s, ")");
  }

  /* [RIP+disp] PC relative addressing in 64 bit mode. */
  else if (p->flags & X86_INSN_PARSE_64_BIT)
    s = format(s, "(%%rip)");

  return s;
}

static u8 *format_x86_insn_operand(u8 *s, va_list *va) {
  x86_insn_parse_t *p    = va_arg(*va, x86_insn_parse_t *);
  x86_insn_t *      insn = &p->insn;
  u32               o    = va_arg(*va, u32);
  u8                c, t;

  ASSERT(o < ARRAY_LEN(insn->operands));
  c = insn->operands[o].code;
  t = insn->operands[o].type;

  /* Register encoded in instruction. */
  if (c < 8)
    return format(s, "%U", format_x86_gp_reg_operand, c, p->log2_effective_operand_bytes);

  switch (c) {
  /* Memory or reg field from modrm byte. */
  case 'M':
    ASSERT(p->flags & X86_INSN_IS_ADDRESS);
    /* FALLTHROUGH */
  case 'E':
    if (p->flags & X86_INSN_IS_ADDRESS)
      s = format(s, "%U", format_x86_mem_operand, p);
    else
      s = format(s, "%U", format_x86_reg_operand, p->regs[1], p->log2_effective_operand_bytes, t);
    break;

  /* reg field from modrm byte. */
  case 'R':
  case 'G':
    s = format(s, "%U", format_x86_reg_operand, p->regs[0], p->log2_effective_operand_bytes, t);
    break;

  case 'I': {
    u32 l    = x86_insn_log2_immediate_bytes(p, insn);
    i64 mask = pow2_mask(8ULL << l);
    s        = format(s, "$0x%Lx", p->immediate & mask);
  } break;

  case 'J':
    if (p->immediate < 0)
      s = format(s, "- 0x%Lx", -p->immediate);
    else
      s = format(s, "+ 0x%Lx", p->immediate);
    break;

  case 'O':
    s = format(s, "0x%Lx", p->immediate);
    break;

  case 'A':
    /* AX/AL */
    s = format(s, "%U", format_x86_gp_reg_operand, X86_INSN_GP_REG_AX, t == 'L' ? 0 : p->log2_effective_operand_bytes);
    break;

  case 'B':
    /* BX/BL/BP */
    s = format(s, "%U", format_x86_gp_reg_operand, t == 'P' ? X86_INSN_GP_REG_BP : X86_INSN_GP_REG_BX,
               t == 'L' ? 0 : p->log2_effective_operand_bytes);
    break;

  case 'C':
    /* CX/CL */
    s = format(s, "%U", format_x86_gp_reg_operand, X86_INSN_GP_REG_CX, t == 'L' ? 0 : p->log2_effective_operand_bytes);
    break;

  case 'D':
    /* DX/DL/DI */
    s = format(s, "%U", format_x86_gp_reg_operand, t == 'I' ? X86_INSN_GP_REG_DI : X86_INSN_GP_REG_DX,
               t == 'L' ? 0 : p->log2_effective_operand_bytes);
    break;

  case 'S':
    /* SI/SP */
    s = format(s, "%U", format_x86_gp_reg_operand, t == 'I' ? X86_INSN_GP_REG_SI : X86_INSN_GP_REG_SP,
               p->log2_effective_operand_bytes);
    break;

  case '1':
    s = format(s, "1");
    break;

  default:
    ASSERT(0);
  }

  return s;
}

u8 *format_x86_insn_parse(u8 *s, va_list *va) {
  x86_insn_parse_t *p    = va_arg(*va, x86_insn_parse_t *);
  x86_insn_t *      insn = &p->insn;
  u32               o, i, is_src_dst;

  s = format(s, "%s", insn->name);

  if (!x86_insn_operand_is_valid(insn, 0))
    goto done;

  is_src_dst = x86_insn_operand_is_valid(insn, 1);

  /* If instruction has immediate add suffix to opcode to
     indicate operand size. */
  if (is_src_dst) {
    u32 b;

    b = x86_insn_log2_immediate_bytes(p, insn);
    if (b < p->log2_effective_operand_bytes && (p->flags & X86_INSN_IS_ADDRESS))
      s = format(s, "%c", "bwlq"[b]);
  }

  for (i = 0; i < ARRAY_LEN(insn->operands); i++) {
    o = is_src_dst + i;
    if (!x86_insn_operand_is_valid(insn, o))
      break;
    s = format(s, "%s%U", i == 0 ? " " : ", ", format_x86_insn_operand, p, o);
  }

  if (is_src_dst)
    s = format(s, ", %U", format_x86_insn_operand, p, 0);

done:
  return s;
}
