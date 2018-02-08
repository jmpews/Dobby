.macro CTX_SAVE_ALL_MACRO
// store {q0-q7}
sub sp, sp, #(8*16)
stp q6, q7, [sp, #(6*16)]
stp q4, q5, [sp, #(4*16)]
stp q2, q3, [sp, #(2*16)]
stp q0, q1, [sp, #(0*16)]

// store {x1-x30}
sub sp, sp, #(30*8)
// stp fp, lr, [sp, #(28*8)]
stp x29, x30, [sp, #(28*8)]
stp x27, x28, [sp, #(26*8)]
stp x25, x26, [sp, #(24*8)]
stp x23, x24, [sp, #(22*8)]
stp x21, x22, [sp, #(20*8)]
stp x19, x20, [sp, #(18*8)]
stp x17, x18, [sp, #(16*8)]
stp x15, x16, [sp, #(14*8)]
stp x13, x14, [sp, #(12*8)]
stp x11, x12, [sp, #(10*8)]
stp x9, x10, [sp, #(8*8)]
stp x7, x8, [sp, #(6*8)]
stp x5, x6, [sp, #(4*8)]
stp x3, x4, [sp, #(2*8)]
stp x1, x2, [sp, #(0*8)]

// C6.1.3
// Use of the stack pointer
// store x0 (and reserve sp, but this is trick.)
sub sp, sp, #(2*8)
str x0, [sp, #8]
.endm

.macro CTX_RESTORE_ALL_MACRO
// C6.1.3
// Use of the stack pointer
// restore x0
ldr x0, [sp, #8]
add sp, sp, #(2*8)

// restore {x1-x30}
ldp x1, x2, [sp], #16
ldp x3, x4, [sp], #16
ldp x5, x6, [sp], #16
ldp x7, x8, [sp], #16
ldp x9, x10, [sp], #16
ldp x11, x12, [sp], #16
ldp x13, x14, [sp], #16
ldp x15, x16, [sp], #16
ldp x17, x18, [sp], #16
ldp x19, x20, [sp], #16
ldp x21, x22, [sp], #16
ldp x23, x24, [sp], #16
ldp x25, x26, [sp], #16
ldp x27, x28, [sp], #16
// ldp fp, lr, [sp], #16
ldp x29, x30, [sp], #16

// restore {q0-q7}
ldp q0, q1, [sp], #32
ldp q2, q3, [sp], #32
ldp q4, q5, [sp], #32
ldp q6, q7, [sp], #32
.endm

// TODO: just macro tips
.macro ctx_save_macrox xcount, xregs:vararg
sub sp, sp, #(\xcount * 8)
.irp reg, \xregs
str \reg, [sp, #8]
.endr
.endm
