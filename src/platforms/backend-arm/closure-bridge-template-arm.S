// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.globl cdecl(closure_bridge_trampoline_template)
.globl cdecl(closure_bridge_template)

cdecl(closure_bridge_trampoline_template):
    .arm
    ldr r7, [pc, #0]
    ldr pc, [pc, #0]
    .long 0
    .long 0

cdecl(closure_bridge_template):
    .arm
    sub sp, sp, #(14*4)
    str lr, [sp, #(13*4)]
    str r12, [sp, #(12*4)]
    str r11, [sp, #(11*4)]
    str r10, [sp, #(10*4)]
    str r9, [sp, #(9*4)]
    str r8, [sp, #(8*4)]
    str r7, [sp, #(7*4)]
    str r6, [sp, #(6*4)]
    str r5, [sp, #(5*4)]
    str r4, [sp, #(4*4)]
    str r3, [sp, #(3*4)]
    str r2, [sp, #(2*4)]
    str r1, [sp, #(1*4)]
    str r0, [sp, #(0*4)]

    // dummy align
    sub sp, sp, #8

    mov r0, sp
    mov r1, r7
    bl  cdecl(common_bridge_handler)

    // dummy align
    add sp, sp, #8

    ldr r0, [sp], #4
    ldr r1, [sp], #4
    ldr r2, [sp], #4
    ldr r3, [sp], #4
    ldr r4, [sp], #4
    ldr r5, [sp], #4
    ldr r6, [sp], #4
    ldr r7, [sp], #4
    ldr r8, [sp], #4
    ldr r9, [sp], #4
    ldr r10, [sp], #4
    ldr r11, [sp], #4
    ldr r12, [sp], #4
    ldr lr, [sp], #4

#if 1
    str r7, [sp, #-4]
    ldr pc, [sp, #-4]
#else
    mov pc, r7
#endif
