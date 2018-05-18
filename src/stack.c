#include <stdlib.h>
#include <string.h>

#include "stack.h"

ThreadStack *ThreadStackGetByThreadLocalKey(zz_ptr_t thread_local_key) {
    ThreadStack *threadstack = (ThreadStack *)ThreadGetThreadLocalValue(thread_local_key);
    if (!threadstack)
        return NULL;
    return threadstack;
}

ThreadStack *ThreadStackAllocate(zz_ptr_t thread_local_key) {
    ThreadStack *threadstack;
    threadstack                    = (ThreadStack *)malloc0(sizeof(ThreadStack));
    threadstack->capacity          = 4;
    CallStack **callstack_ptr_list = (CallStack **)malloc0(sizeof(CallStack *) * (threadstack->capacity));
    if (!callstack_ptr_list)
        return NULL;
    threadstack->callstack_ptr_list = callstack_ptr_list;
    threadstack->size               = 0;
    threadstack->thread_local_key   = thread_local_key;
    threadstack->thread_id          = ThreadGetCurrentThreadID();
    ThreadSetThreadLocalValue(thread_local_key, (zz_ptr_t)threadstack);
    return threadstack;
}

CallStack *CallStackAllocate() {
    CallStack *callstack;
    callstack                       = (CallStack *)malloc0(sizeof(CallStack));
    callstack->capacity             = 4;
    callstack->callstack_entry_list = (CallStackEntry *)malloc(sizeof(CallStackEntry) * callstack->capacity);
    callstack->size                 = 0;
    if (!callstack->callstack_entry_list)
        return NULL;
    return callstack;
}

void CallStackFree(CallStack *callstack) {
    free(callstack->callstack_entry_list);
    free(callstack);
    callstack = NULL;
}

CallStack *ThreadStackPopCallStack(ThreadStack *stack) {
    if (stack->size > 0)
        stack->size--;
    else
        return NULL;
    CallStack *callstack = stack->callstack_ptr_list[stack->size];
    return callstack;
}

bool ThreadStackPushCallStack(ThreadStack *stack, CallStack *callstack) {
    if (!stack)
        return FALSE;

    if (stack->size >= stack->capacity) {
        // add extra callstack_ptr_list
        CallStack **callstack_ptr_list =
            (CallStack **)realloc(stack->callstack_ptr_list, sizeof(CallStack *) * (stack->capacity) * 2);
        if (!callstack_ptr_list)
            return FALSE;
        stack->callstack_ptr_list = callstack_ptr_list;
        stack->capacity           = stack->capacity * 2;
    }

    callstack->call_id     = stack->size;
    callstack->threadstack = (ThreadStack *)stack;

    stack->callstack_ptr_list[stack->size++] = callstack;
    return TRUE;
}

zz_ptr_t CallStackGetThreadLocalData(CallStackPublic *callstack_ptr, char *key) {
    CallStack *callstack = (CallStack *)callstack_ptr;
    if (!callstack)
        return NULL;
    int i;
    for (i = 0; i < callstack->size; ++i) {
        if (!strcmp(callstack->callstack_entry_list[i].key, key)) {
            return callstack->callstack_entry_list[i].value;
        }
    }
    return NULL;
}

CallStackEntry *CallStackAllocateData(CallStack *callstack) {
    if (!callstack)
        return NULL;
    if (callstack->size >= callstack->capacity) {
        // add extra callstackcallstack_entry_list
        CallStackEntry *callstackcallstack_entry_list = (CallStackEntry *)realloc(
            callstack->callstack_entry_list, sizeof(CallStackEntry) * callstack->capacity * 2);
        if (!callstackcallstack_entry_list)
            return NULL;
        callstack->callstack_entry_list = callstackcallstack_entry_list;
        callstack->capacity             = callstack->capacity * 2;
    }
    return &(callstack->callstack_entry_list[callstack->size++]);
}

bool CallStackSetThreadLocalData(CallStackPublic *callstack_ptr, char *key, zz_ptr_t value_ptr, zz_size_t value_size) {
    CallStack *callstack = (CallStack *)callstack_ptr;
    if (!callstack)
        return FALSE;

    CallStackEntry *item = CallStackAllocateData(callstack);

    char *key_tmp = (char *)malloc0(strlen(key) + 1);
    strncpy(key_tmp, key, strlen(key) + 1);

    zz_ptr_t value_tmp = (zz_ptr_t)malloc0(value_size);
    memcpy(value_tmp, value_ptr, value_size);
    item->key   = key_tmp;
    item->value = value_tmp;
    return TRUE;
}
