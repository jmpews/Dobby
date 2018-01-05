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

#define HOOK_FUNCTION_TYPE 1
#define HOOK_ADDRESS_TYPE 2

struct _ZzInterceptor;
struct _ZzHookFunctionEntryBackend;
typedef struct _ZzHookFunctionEntry {
    int hook_type;
    unsigned long id;
    bool isEnabled;
    bool try_near_jump;

    zz_ptr_t thread_local_key;

    zz_ptr_t target_ptr;
    zz_ptr_t target_end_ptr;
    zz_ptr_t target_half_ret_addr;

    zz_ptr_t pre_call;
    zz_ptr_t half_call;
    zz_ptr_t post_call;
    zz_ptr_t replace_call;

    zz_ptr_t on_enter_transfer_trampoline;
    zz_ptr_t on_enter_trampoline;
    zz_ptr_t on_half_trampoline;
    zz_ptr_t on_invoke_trampoline;
    zz_ptr_t on_leave_trampoline;

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
    ZzHookFunctionEntrySet hook_function_entry_set;
    struct _ZzInterceptorBackend *backend;
    ZzAllocator *allocator;
} ZzInterceptor;

#endif