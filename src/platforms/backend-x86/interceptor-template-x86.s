// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

##if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.align 4

.globl cdecl(ctx_save)
.globl cdecl(ctx_restore)
.globl cdecl(enter_thunk_template)
.globl cdecl(leave_thunk_template)
.globl cdecl(on_enter_trampoline_template)
.globl cdecl(on_invoke_trampoline_template)
.globl cdecl(on_leave_trampoline_template)
