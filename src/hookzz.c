#include "hookzz.h"
#include "core.h"
#include "interceptor.h"
#include "interceptor_routing_trampoline.h"
#include "std_kit/std_kit.h"

static void initialize_hook_entry(hook_entry_t *entry) {
    interceptor_t *interceptor = interceptor_cclass(shared_instance)();
    interceptor_cclass(add_hook_entry)(interceptor, entry);
    interceptor_trampoline_cclass(build_all)(entry);
    interceptor_trampoline_cclass(active)(entry);
}

RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call) {
    hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
    entry->target_address = function_address;
    entry->type           = HOOK_TYPE_FUNCTION_via_PRE_POST;
    entry->pre_call       = pre_call;
    entry->post_call      = post_call;

    initialize_hook_entry(entry);

    return RS_SUCCESS;
}

RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call) {
    hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
    entry->target_address = function_address;
    entry->type           = HOOK_TYPE_FUNCTION_via_REPLACE;
    entry->replace_call   = replace_call;

    initialize_hook_entry(entry);

    return RS_SUCCESS;
}

RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call) {
    hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
    entry->target_address = inst_address;
    entry->type           = HOOK_TYPE_INSTRUCTION_via_DBI;
    entry->dbi_call       = dbi_call;

    initialize_hook_entry(entry);

    return RS_SUCCESS;
}