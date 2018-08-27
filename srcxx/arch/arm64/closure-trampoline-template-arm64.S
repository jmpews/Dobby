// .section	__TEXT,__text,regular,pure_instructions

#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.align 4

#if defined(ENABLE_CLOSURE_TRAMPOLINE_CARRY_OBJECT_PTR)

// closure trampoline carray the object pointer, and fetch required members at the runtime assembly code.
#include "srcxx/AssemblyClosureTrampoline.h"
#define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
.globl cdecl(closure_bridge_trampoline_template)
cdecl(closure_bridge_trampoline_template):
    ldr x17, =ClourseTrampolineEntryPtr
    ldr x16, OFFSETOF(ClourseTrampolineEntry, carray_data)
    ldr x17, OFFSETOF(ClourseTrampolineEntry, forward_code)
    br x17
ClourseTrampolineEntryPtr:
    .long 0
    .long 0

#else

// closure trampoline just carray the required members from the object.
.globl cdecl(closure_bridge_trampoline_template)
cdecl(closure_bridge_trampoline_template):
    ldr x16, =carray_data
    ldr x17, =forward_code
    br x17
carray_data:
    .long 0
    .long 0
forward_code:
    .long 0
    .long 0

#endif