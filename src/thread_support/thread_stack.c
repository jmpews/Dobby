
#include "thread_stack.h"
#include "core.h"
#include "thread_local_storage.h"

thread_stack_manager_t *thread_stack_cclass(shared_instance)() {
    thread_stack_manager_t *g_thread_stack_manager = (thread_stack_manager_t *)get_thread_variable_value();
    if (g_thread_stack_manager == NULL) {
        g_thread_stack_manager              = SAFE_MALLOC_TYPE(thread_stack_manager_t);
        g_thread_stack_manager->call_stacks = list_new();
        set_thread_variable_value((void *)g_thread_stack_manager);
    }

    return g_thread_stack_manager;
}

void thread_stack_cclass(push_call_stack)(thread_stack_manager_t *self, call_stack_t *call_stack) {
    list_rpush(self->call_stacks, list_node_new(call_stack));
}

call_stack_t *thread_stack_cclass(pop_call_stack)(thread_stack_manager_t *self) {
    call_stack_t *call_stack = (call_stack_t *)(list_rpop(self->call_stacks)->val);
    return call_stack;
}

call_stack_t *call_stack_cclass(new)(thread_stack_manager_t *thread_stack_manager) {
    call_stack_t *call_stack         = SAFE_MALLOC_TYPE(call_stack_t);
    call_stack->call_id              = thread_stack_manager->call_stacks->len;
    call_stack->context_kv           = map_new();
    call_stack->thread_stack_manager = thread_stack_manager;
    return call_stack;
}

void call_stack_cclass(destory)(call_stack_t *self) {
    map_destory(self->context_kv);
    SAFE_FREE(self);
}