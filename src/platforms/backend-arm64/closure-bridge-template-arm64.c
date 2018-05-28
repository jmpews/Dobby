
#define ASM(x) asm(x)
void closure_bridge_template() {
    // prologue
    ASM("stp		fp, lr, [sp, #-16]!");
    ASM("mov		fp, sp");

    // save {q0-q7}
    ASM("sub sp, sp, #(8*16)");
    ASM("stp q6, q7, [sp, #(6*16)]");
    ASM("stp q4, q5, [sp, #(4*16)]");
    ASM("stp q2, q3, [sp, #(2*16)]");
    ASM("stp q0, q1, [sp, #(0*16)]");

    // save {x1-x30}
    ASM("sub sp, sp, #(30*8)");
    // stp fp, lr, [sp, #(28*8)]");
    ASM("stp x29, x30, [sp, #(28*8)]");
    ASM("stp x27, x28, [sp, #(26*8)]");
    ASM("stp x25, x26, [sp, #(24*8)]");
    ASM("stp x23, x24, [sp, #(22*8)]");
    ASM("stp x21, x22, [sp, #(20*8)]");
    ASM("stp x19, x20, [sp, #(18*8)]");
    ASM("stp x17, x18, [sp, #(16*8)]");
    ASM("stp x15, x16, [sp, #(14*8)]");
    ASM("stp x13, x14, [sp, #(12*8)]");
    ASM("stp x11, x12, [sp, #(10*8)]");
    ASM("stp x9, x10, [sp, #(8*8)]");
    ASM("stp x7, x8, [sp, #(6*8)]");
    ASM("stp x5, x6, [sp, #(4*8)]");
    ASM("stp x3, x4, [sp, #(2*8)]");
    ASM("stp x1, x2, [sp, #(0*8)]");

#if 1
    // save {x0}
    ASM("sub sp, sp, #(2*8)");
    ASM("str x0, [sp, #8]");
#else
    // save {x0, sp}
    // save x0 and reserve sp, but this is trick
    ASM("sub sp, sp, #(2*8)");
    ASM("str x0, [sp, #8]");
    // save origin sp
    ASM("add x1, sp, #0x190");
    ASM("str x1, [sp, #0]");
#endif

    // ======= Jump to Common Bridge Handle =======

    // prepare args
    // @x0: data_address
    // @x1: RegState stack address
    ASM("mov x0, sp");
    ASM("mov x1, x14");
    ASM("bl _common_bridge_handler");

    // ======= RegState Restore =======
    // restore x0
    ASM("ldr x0, [sp, #8]");
    ASM("add sp, sp, #(2*8)");

    // restore {x1-x30}
    ASM("ldp x1, x2, [sp], #16");
    ASM("ldp x3, x4, [sp], #16");
    ASM("ldp x5, x6, [sp], #16");
    ASM("ldp x7, x8, [sp], #16");
    ASM("ldp x9, x10, [sp], #16");
    ASM("ldp x11, x12, [sp], #16");
    ASM("ldp x13, x14, [sp], #16");
    ASM("ldp x15, x16, [sp], #16");
    ASM("ldp x17, x18, [sp], #16");
    ASM("ldp x19, x20, [sp], #16");
    ASM("ldp x21, x22, [sp], #16");
    ASM("ldp x23, x24, [sp], #16");
    ASM("ldp x25, x26, [sp], #16");
    ASM("ldp x27, x28, [sp], #16");
    // ldp fp, lr, [sp], #16");
    ASM("ldp x29, x30, [sp], #16");

    // restore {q0-q7}
    ASM("ldp q0, q1, [sp], #32");
    ASM("ldp q2, q3, [sp], #32");
    ASM("ldp q4, q5, [sp], #32");
    ASM("ldp q6, q7, [sp], #32");

    // epilog
    ASM("mov		sp, fp");
    ASM("ldp		fp, lr, [sp], #16");

    ASM("br x15");
};