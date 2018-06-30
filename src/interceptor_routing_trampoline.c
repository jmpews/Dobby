#include "interceptor_routing_trampoline.h"

void interceptor_trampoline_cclass(build_all)(hook_entry_t *entry) {
    if (entry->type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
        interceptor_trampoline_cclass(prepare)(entry);
        interceptor_trampoline_cclass(build_for_enter)(entry);
        interceptor_trampoline_cclass(build_for_invoke)(entry);
        interceptor_trampoline_cclass(build_for_leave)(entry);
    } else if (entry->type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        interceptor_trampoline_cclass(prepare)(entry);
        interceptor_trampoline_cclass(build_for_enter_transfer)(entry);
        interceptor_trampoline_cclass(build_for_invoke)(entry);
    } else if (entry->type == HOOK_TYPE_FUNCTION_via_GOT) {
        // trampoline_prepare(self, entry);
        interceptor_trampoline_cclass(build_for_enter)(entry);
        interceptor_trampoline_cclass(build_for_leave)(entry);
    } else if (entry->type == HOOK_TYPE_INSTRUCTION_via_DBI) {
        interceptor_trampoline_cclass(prepare)(entry);
        interceptor_trampoline_cclass(build_for_dynamic_binary_instrumentation)(entry);
        interceptor_trampoline_cclass(build_for_invoke)(entry);
    }
    return;
}
