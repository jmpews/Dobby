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