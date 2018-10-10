#ifndef macros_h
#define macros_h

#include <stdint.h>

#define INT5_MASK 0x0000001f
#define INT8_MASK 0x000000ff
#define INT10_MASK 0x000003ff
#define INT11_MASK 0x000007ff
#define INT12_MASK 0x00000fff
#define INT14_MASK 0x00003fff
#define INT16_MASK 0x0000ffff
#define INT18_MASK 0x0003ffff
#define INT19_MASK 0x0007ffff
#define INT24_MASK 0x00ffffff
#define INT26_MASK 0x03ffffff
#define INT28_MASK 0x0fffffff

#define THUMB_FUNCTION_ADDRESS(address) ((uintptr_t)address & ~(uintptr_t)1)
#define INSTRUCTION_IS_THUMB(insn_addr) (((uintptr_t)insn_addr & 0x1) == 0x1)

#define ALIGN_FLOOR(address, range) ((uintptr_t)address & ~((uintptr_t)range - 1))
#define ALIGN_CEIL(address, range) (((uintptr_t)address + (uintptr_t)range - 1) & ~((uintptr_t)range - 1))

#endif