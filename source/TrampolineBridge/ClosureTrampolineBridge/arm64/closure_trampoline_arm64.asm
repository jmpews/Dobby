#if defined(__arm64__) || defined(__aarch64__)
#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

#define TMP_REG_0 x17

.align 4

.globl cdecl(closure_trampoline_asm)

cdecl(closure_trampoline_asm):
// prologue: alloc stack, store lr
sub sp, sp, #(2 * 8)
str x30, [sp, #8]

// store data at stack
ldr TMP_REG_0, #closure_tramp_entry_addr
str TMP_REG_0, [sp, #0]

ldr TMP_REG_0, #closure_bridge_addr
blr TMP_REG_0

// epilogue: release stack(won't restore lr)
ldr x30, [sp, #8]
add sp, sp, #(2 * 8)

// branch to next hop
br TMP_REG_0

closure_tramp_entry_addr:
.quad 0

closure_bridge_addr:
.quad 0

.globl cdecl(closure_trampoline_asm_end)
cdecl(closure_trampoline_asm_end):
#endif