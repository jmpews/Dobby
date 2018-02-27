#ifndef interceptor_h
#define interceptor_h

#include "hookzz.h"
#include "kitzz.h"

#include "allocator.h"
#include "stack.h"
#include "thread.h"
#include "thunker.h"
#include "writer.h"

typedef struct _FunctionBackup {
    zz_ptr_t address;
    zz_size_t size;
    char data[32];
} FunctionBackup;

struct _ZzInterceptor;
struct _ZzHookFunctionEntryBackend;
typedef struct _ZzHookFunctionEntry {
    ZZHOOKTYPE hook_type;
    unsigned long id;
    bool isEnabled;
    bool try_near_jump;

    zz_ptr_t thread_local_key;

    zz_ptr_t target_ptr;

    zz_addr_t next_insn_addr; // hook one instruction next insn addr

    zz_ptr_t pre_call;
    zz_ptr_t post_call;
    zz_ptr_t stub_call;
    zz_ptr_t replace_call;

    zz_ptr_t on_enter_transfer_trampoline;
    zz_ptr_t on_enter_trampoline;
    zz_ptr_t on_insn_leave_trampoline;
    zz_ptr_t on_invoke_trampoline;
    zz_ptr_t on_leave_trampoline;
    zz_ptr_t on_dynamic_binary_instrumentation_trampoline;

    FunctionBackup origin_prologue;
    struct _ZzHookFunctionEntryBackend *backend;
    struct _ZzInterceptor *interceptor;
} ZzHookFunctionEntry;

typedef struct {
    ZzHookFunctionEntry **entries;
    zz_size_t size;
    zz_size_t capacity;
} ZzHookFunctionEntrySet;

struct _ZzInterceptorBackend;
typedef struct _ZzInterceptor {
    bool is_support_rx_page;
    bool default_trampoline_try_near_jump;
    ZzHookFunctionEntrySet hook_function_entry_set;
    struct _ZzInterceptorBackend *backend;
    ZzAllocator *allocator;
} ZzInterceptor;

ZZSTATUS ZzBuildHookGOT(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                        POSTCALL post_call_ptr);
ZZSTATUS ZzDisableHookGOT(const char *name);

void ZzFreeHookFunctionEntry(ZzHookFunctionEntry *entry);
#endif