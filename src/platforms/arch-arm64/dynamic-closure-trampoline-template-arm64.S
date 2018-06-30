#if DYNAMIC_CLOSURE_BRIDGE

// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

#if defined(__WIN32__) || defined(__APPLE__)
    #define cdecl(s) _##s
#else
    #define cdecl(s) s
#endif

#define PAGE_MAX_SIZE 4096
#define PAGE_MAX_SHIFT 14

.align PAGE_MAX_SHIFT
.globl cdecl(dynamic_closure_trampoline_table_page)
cdecl(dynamic_closure_trampoline_table_page):
.rept  (PAGE_MAX_SIZE - 4 * 4) / 8 // sub dynamic_closure_trampoline_forward_length
adr x14, #0
b cdecl(dynamic_closure_trampoline_forward)
.endr

cdecl(dynamic_closure_trampoline_forward):
sub x14, x14, #0x4000 // [DynamicClosureTrampoline **]
ldr x14, [x14, #0] // [DynamicClosureTrampoline *]
ldr x15, [x14, #0] // trampolineTo 
br x15

#endif