// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

#if defined(__WIN32__) || defined(__APPLE__)
    #define cdecl(s) _##s
#else
    #define cdecl(s) s
#endif

#define PAGE_MAX_SIZE 4096
#define PAGE_MAX_SHIFT 12

.align PAGE_MAX_SHIFT
.globl cdecl(dynamic_closure_trampoline_table_page)
cdecl(dynamic_closure_trampoline_table_page):
.rept  (PAGE_MAX_SIZE - 0x24 * 4) / 8
adr x16, #0
b cdecl(closure_bridge_template)
.endr