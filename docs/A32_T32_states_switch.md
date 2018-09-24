Writing to the PC

In the A32 and T32 instruction sets, many data-processing instructions can write to the PC. Writes to the PC are handled as follows:

* In T32 state, the following 16-bit T32 instruction encodings branch to the value written to the PC:

  - Encoding T2 of ADD, ADDS (register) on page F5-2573.

  - Encoding T1 of MOV, MOVS (register) on page F5-2815.

* The value written to the PC is forced to be halfword-aligned by ignoring its least significant bit, treating that bit as being 0.

* The B, BL, CBNZ, CBZ, CHKA, HB, HBL, HBLP, HBP, TBB, and TBH instructions remain in the same instruction set state and branch to the value written to the PC.

* The definition of each of these instructions ensures that the value written to the PC is correctly aligned for the current instruction set state.

* The BLX (immediate) instruction switches between A32 and T32 states and branches to the value written to the PC. Its definition ensures that the value written to the PC is correctly aligned for the new instruction set state.

* The following instructions write a value to the PC, treating that value as an interworking address to branch to, with low-order bits that determine the new instruction set state:

  - BLX (register), BX, and BXJ.

  - LDR instructions with <Rt> equal to the PC.

  - POP and all forms of LDM except LDM (exception return), when the register list includes the PC.

- In A32 state only, ADC, ADD, ADR, AND, ASR (immediate), BIC, EOR, LSL (immediate), LSR (immediate), MOV,

MVN, ORR, ROR (immediate), RRX, RSB, RSC, SBC, and SUB instructions with <Rd> equal to the PC and without

flag-setting specified.