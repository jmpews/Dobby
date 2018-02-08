#include <stdlib.h>
#include <string.h>

#include "stack.h"

ZzThreadStack *ZzGetCurrentThreadStack(zz_ptr_t key_ptr) {
    ZzThreadStack *threadstack = (ZzThreadStack *)ZzThreadGetCurrentThreadData(key_ptr);
    if (!threadstack)
        return NULL;
    return threadstack;
}

ZzThreadStack *ZzNewThreadStack(zz_ptr_t key_ptr) {
    ZzThreadStack *threadstack;
    threadstack              = (ZzThreadStack *)zz_malloc_with_zero(sizeof(ZzThreadStack));
    threadstack->capacity    = 4;
    ZzCallStack **callstacks = (ZzCallStack **)zz_malloc_with_zero(sizeof(ZzCallStack *) * (threadstack->capacity));
    if (!callstacks)
        return NULL;
    threadstack->callstacks = callstacks;
    threadstack->size       = 0;
    threadstack->key_ptr    = key_ptr;
    threadstack->thread_id  = ZzThreadGetCurrentThreadID();
    ZzThreadSetCurrentThreadData(key_ptr, (zz_ptr_t)threadstack);
    return threadstack;
}

ZzCallStack *ZzNewCallStack() {
    ZzCallStack *callstack;
    callstack           = (ZzCallStack *)zz_malloc_with_zero(sizeof(ZzCallStack));
    callstack->capacity = 4;
    callstack->items    = (ZzCallStackItem *)malloc(sizeof(ZzCallStackItem) * callstack->capacity);
    callstack->size     = 0;
    if (!callstack->items)
        return NULL;
    return callstack;
}

void ZzFreeCallStack(ZzCallStack *callstack) {
    free(callstack->items);
    free(callstack);
    callstack = NULL;
}

ZzCallStack *ZzPopCallStack(ZzThreadStack *stack) {
    if (stack->size > 0)
        stack->size--;
    else
        return NULL;
    ZzCallStack *callstack = stack->callstacks[stack->size];
    return callstack;
}

bool ZzPushCallStack(ZzThreadStack *stack, ZzCallStack *callstack) {
    if (!stack)
        return FALSE;

    if (stack->size >= stack->capacity) {
        // add extra callstacks
        ZzCallStack **callstacks =
            (ZzCallStack **)realloc(stack->callstacks, sizeof(ZzCallStack *) * (stack->capacity) * 2);
        if (!callstacks)
            return FALSE;
        stack->callstacks = callstacks;
        stack->capacity   = stack->capacity * 2;
    }

    callstack->call_id     = stack->size;
    callstack->threadstack = (ThreadStack *)stack;

    stack->callstacks[stack->size++] = callstack;
    return TRUE;
}

zz_ptr_t ZzGetCallStackData(CallStack *callstack_ptr, char *key) {
    ZzCallStack *callstack = (ZzCallStack *)callstack_ptr;
    if (!callstack)
        return NULL;
    int i;
    for (i = 0; i < callstack->size; ++i) {
        if (!strcmp(callstack->items[i].key, key)) {
            return callstack->items[i].value;
        }
    }
    return NULL;
}

ZzCallStackItem *ZzNewCallStackData(ZzCallStack *callstack) {
    if (!callstack)
        return NULL;
    if (callstack->size >= callstack->capacity) {
        // add extra callstackitems
        ZzCallStackItem *callstackitems =
            (ZzCallStackItem *)realloc(callstack->items, sizeof(ZzCallStackItem) * callstack->capacity * 2);
        if (!callstackitems)
            return NULL;
        callstack->items    = callstackitems;
        callstack->capacity = callstack->capacity * 2;
    }
    return &(callstack->items[callstack->size++]);
}

bool ZzSetCallStackData(CallStack *callstack_ptr, char *key, zz_ptr_t value_ptr, zz_size_t value_size) {
    ZzCallStack *callstack = (ZzCallStack *)callstack_ptr;
    if (!callstack)
        return FALSE;

    ZzCallStackItem *item = ZzNewCallStackData(callstack);

    char *key_tmp = (char *)zz_malloc_with_zero(strlen(key) + 1);
    strncpy(key_tmp, key, strlen(key) + 1);

    zz_ptr_t value_tmp = (zz_ptr_t)zz_malloc_with_zero(value_size);
    memcpy(value_tmp, value_ptr, value_size);
    item->key   = key_tmp;
    item->value = value_tmp;
    return TRUE;
}
