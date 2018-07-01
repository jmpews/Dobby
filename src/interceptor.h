#ifndef interceptor_h
#define interceptor_h

#include "core.h"
#include "hookzz.h"
#include "memory_manager.h"

typedef struct _FunctionBackup {
    void *address;
    int size;
    char data[32];
} FunctionBackup;

struct _interceptor_t;
struct _hook_entry_backend_t;
typedef struct _hook_entry_t {
    void *target_address;

    HookType type;

    uintptr_t id;

    bool is_enable;

    bool is_try_near_jump;

    bool is_near_jump;

    PRECALL pre_call;
    POSTCALL post_call;
    DBICALL dbi_call;
    void *replace_call;

    void *on_enter_transfer_trampoline;
    void *on_enter_trampoline;
    void *on_invoke_trampoline;
    void *on_leave_trampoline;
    void *on_dynamic_binary_instrumentation_trampoline;

    FunctionBackup origin_prologue;
    struct _hook_entry_backend_t *backend;
    struct _interceptor_t *interceptor;
} hook_entry_t;

struct _interceptor_backend_t;

typedef struct _interceptor_t {

    bool is_support_rx_memory;

    list_t *hook_entries;

    struct _interceptor_backend_t *interceptor_backend;

    memory_manager_t *memory_manager;
} interceptor_t;

#define interceptor_cclass(member) cclass(interceptor, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

interceptor_t *interceptor_cclass(shared_instance)(void);

hook_entry_t *interceptor_cclass(find_hook_entry)(interceptor_t *self, void *target_address);

void interceptor_cclass(add_hook_entry)(interceptor_t *self, hook_entry_t *entry);

void interceptor_cclass(initialize_interceptor_backend)();

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
