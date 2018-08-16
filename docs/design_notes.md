#### temporary place
```
op NOT vixl NOT Android NOT V8 NOT mozilla NOT Dolphin filename:arm64 extension:cpp
imm NOT uiCacheOp NOT CSSELR NOT Capstone NOT apple NOT Valgrind filename:arm64 extension:c
aarch64 NOT Gabe aarch64 in:file,path filename:decoder
```

#### thumb instruct fixed scheme
```
# origin
adr r0, #0x2

# scheme-1-fixed [DO NOT USE]
mov.w r7, #offset
adr r0, #0x2
add.w r0, r0, r7

# scheme-2-fixed [DO NOT USE]
0x4: ldr.w R0, [pc, #0x0]
0x8: b.w 0x2
0xc: .long 0

# scheme-3-fixed  [USE THIS]
0x4: ldr.w R0, [pc, #label]
```

#### arm & thumb & thumb2 need fix up

```
Instructions that explicitly write to the PC (branches)
These instructions are:
• B, B (conditional), CBZ, CBNZ BL.
• BX, BLX (register or immediate).
• BXJ, TBB, TBH.
• MOV pc and related instructions.
• LDR pc, LDM (with a register list includes the PC), POP (with a register list that includes the PC).

Instructions that read the PC
These instructions are:
• LDR (literal), LDRB (literal), LDRH (literal), LDRSB (literal), LDRSH (literal).
• ADR, ADRL, ADRH.
• PLD (literal), PLI (literal).
```

#### ARM64 need fix up
```
Instructions that explicitly write to the PC (branches)
These instructions are:
• B, B.cond, BL, BLR, BR, CBZ, CBNZ, RET, TBZ, TBNZ.

Instructions that read the PC
These instructions are:
• LDR (literal), LDRSW (literal).
• ADR, ADRP.
• PRFM (literal).
```


#### finaly

instruction fix will follow rules

```
// adr
// load literal
// conditional branch
// unconditional branch
// compare branch (cbz, cbnz)
// branch with link
// tbz, tbnz
```

#### 对于 ARM 指令集可以直接访问 pc

所以对于如下的指令的修复是有困难的

thumb

```
  /* <<SAD: it's too hard to identify all instruction that use pc register>>
  // pc process with other register
  if ((inst & 0xfc00) == 0x4400) {
    uint16_t op = get_insn_sub(inst, 8, 2);
    // cond != 111x
    if (op == 0b11) {
      goto NOT_REWRITE_ROUTINE;
    }
    rd = get_insn_sub(inst, 7, 1) << 3 | get_insn_sub(inst, 0, 3);
    if (rd == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }
  */
```

thumb2

```
  /* <<SAD: it's too hard to identify all instruction that use pc register>>
  // data-processing (shifted register)
  if ((inst1 & 0xfe00) == 0xea00 && (inst2 & 0x8000) == 0) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    uint16_t rm = get_insn_sub(inst2, 0, 4);
    if (rn == 15 || rd == 15 || rm == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // data-processing (modified immediate)
  if ((inst1 & 0xfa00) == 0xf000 && (inst2 & 0x8000) == 0) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // load/store exclusive
  if ((inst1 & 0xffe0) == 0xe840) {
    uint16_t rn = get_insn_sub(inst1, 0, 4);
    uint16_t rd = get_insn_sub(inst2, 8, 4);
    uint16_t rt = get_insn_sub(inst2, 12, 4);
    if (rn == 15 || rd == 15 || rt == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }
  // Load/store exclusive byte/half/dual
  if ((inst1 & 0xffe0) == 0xe8c0 && (inst2 & 0x00c0) == 0x0040) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rd  = get_insn_sub(inst2, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // Load-acquire / Store-release
  if ((inst1 & 0xffe0) == 0xe8c0 && (inst2 & 0x0080) == 0x0080) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rd  = get_insn_sub(inst2, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rd == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  // Load/store dual (immediate, post-indexed)
  if ((inst1 & 0xff60) == 0xe860) {
    uint16_t rn  = get_insn_sub(inst1, 0, 4);
    uint16_t rt  = get_insn_sub(inst2, 12, 4);
    uint16_t rt2 = get_insn_sub(inst2, 8, 4);
    if (rn == 15 || rt == 15 || rt2 == 15) {
      ERROR_NOT_IMPLICATION();
    }
  }

  ...
  */
}
```

#### TOOD_x

`instCTXs` -> `inst_ctx_lst`.

`inst_bytes` -> `inst_byte_ary`