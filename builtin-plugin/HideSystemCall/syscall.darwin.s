#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.section __DATA, __const, regular
.globl cdecl(svc_0x80_stub)
cdecl(svc_0x80_stub):
  .long 0x41414141
  .long 0x41414141

.section __TEXT,__text,regular,pure_instructions
.align 4
.globl cdecl(svc_mprotect)
cdecl(svc_mprotect):
  mov x16, #0x4a
  adrp x17, _svc_0x80_stub@page
  add x17, x17, _svc_0x80_stub@pageoff
  ldr x17, [x17, #0]
  br x17