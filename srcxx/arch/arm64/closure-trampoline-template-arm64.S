// .section	__TEXT,__text,regular,pure_instructions

#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.align 4

.globl cdecl(closure_bridge_trampoline_template)
cdecl(closure_bridge_trampoline_template):
    ldr x14, #0xc
    ldr x15, #0x10
    br x15
    .long 0
    .long 0
    .long 0
    .long 0