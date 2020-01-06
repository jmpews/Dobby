#if 0
ldr x0, #4
nop
nop

nop
nop
ldr x0, #-8

adr x0, #4

adrp x0, #0x1000

tbz x0, #8, #4

tbz x0, #27, #-4

cbz x0, #4

cbz x0, #-4

cmp x0, x0
b.eq #-4
#endif