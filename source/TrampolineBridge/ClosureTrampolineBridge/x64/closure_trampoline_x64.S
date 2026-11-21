#if defined(__x86_64__)
#if defined(__APPLE__) || (defined(__WIN32__) && !defined(__x86_64__))
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.intel_syntax noprefix
.align 4

.globl cdecl(closure_trampoline_asm)

// tip: rip mean next instruction address
cdecl(closure_trampoline_asm):
  push [rip + 6]
  jmp [rip + 8]

closure_tramp_entry_addr:
.quad 0

closure_bridge_addr:
.quad 0

.globl cdecl(closure_trampoline_asm_end)
cdecl(closure_trampoline_asm_end):
#endif