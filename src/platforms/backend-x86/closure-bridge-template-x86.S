// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.align 4

.globl cdecl(closure_bridge_trampoline_template)
.globl cdecl(closure_bridge_template)

cdecl(closure_bridge_trampoline_template):


cdecl(closure_bridge_template):

