#include <string.h>
#include <stdlib.h>
#include "stack.h"
// #include "zzdeps/posix/thread-utils-posix.h"

extern void zz_thread_initialize_thread_local_keys();
extern zpointer zz_thread_new_thread_local_key();
extern zpointer zz_thread_get_current_thread_data(zpointer key_ptr);
extern int zz_thread_set_current_thread_data(zpointer key_ptr, zpointer data);

void ZzInitializeThreadLocalKey() {
    zz_thread_initialize_thread_local_keys();
}

zpointer ZzNewThreadLocalKey() {
    return zz_thread_new_thread_local_key();
}

ZzStack *ZzCurrentThreadStack(zpointer thread_local_key_ptr) {
    ZzStack *stack  = (ZzStack *)zz_thread_get_current_thread_data(thread_local_key_ptr);
    if(!stack) {
        stack = ZzNewStack();
        zz_thread_set_current_thread_data(thread_local_key_ptr, (zpointer)stack);
    }
    return stack;
}

ZzStack * ZzNewStack() {
    ZzStack *stack;
    stack = (ZzStack *)malloc(sizeof(ZzStack));
    stack->capacity = 4;
    ZzCallerStack **caller_stacks = (ZzCallerStack **)malloc(sizeof(ZzCallerStack *) * (stack->capacity));
    if(!caller_stacks)
        return NULL;
    stack->caller_stacks = caller_stacks;
    stack->size = 0;
    return stack;

}

ZzCallerStack *ZzNewCallerStack() {
    ZzCallerStack *caller_stack;
    caller_stack = (ZzCallerStack *)malloc(sizeof(ZzCallerStack));
    caller_stack->capacity = 4;
    char **keys = (char **)malloc(sizeof(char *) * (caller_stack->capacity));
    if (!keys)
    {
        return false;
    }
    zpointer *values = (zpointer *)malloc(sizeof(zpointer) * (caller_stack->capacity));
    if(!values)
        return false;
    caller_stack->keys = keys;
    caller_stack->values = values;
    caller_stack->size = 0;
    return caller_stack;
}
ZzCallerStack *ZzStackPOP(ZzStack *stack) {
	stack->size--;
	ZzCallerStack *caller_stack = stack->caller_stacks[stack->size];
	return caller_stack;
}

ZZSTATUS ZzStackPUSH(ZzStack *stack, ZzCallerStack *caller_stack) {
	if (stack->size >= stack->capacity)
	{
		ZzCallerStack **caller_stacks = (ZzCallerStack **)realloc(stack->caller_stacks, sizeof(ZzCallerStack *) * (stack->capacity) * 2);
		if(!caller_stacks)
			return false;
		stack->caller_stacks = caller_stacks;
		stack->capacity = stack->capacity * 2;
	}

	stack->caller_stacks[stack->size] = caller_stack;
	stack->size++;
	return true;
}

zpointer ZzCallerStackGet(ZzCallerStack *stack , char *key) {
	// ZzStack max keys count.
	for (int i = 0; i < stack->size; ++i)
	{
		if (!strcmp(stack->keys[i], key))
		{
			return stack->values[i];
		}
	}
	return NULL;
}

ZZSTATUS ZzCallerStackSet(ZzCallerStack *stack, char *key, zpointer value_ptr, zsize value_size) {
	if (stack->size >= stack->capacity)
	{
		char **keys = (char **)realloc(stack->keys, sizeof(char *) * (stack->capacity) * 2);
		if (!keys)
		{
			return false;
		}
		zpointer *values = (zpointer *)realloc(stack->values, sizeof(zpointer) * (stack->capacity) * 2);
		if(!values)
			return false;
		stack->keys = keys;
		stack->values = values;
		stack->capacity = stack->capacity * 2;
	}

	char *key_tmp = (char *)malloc(strlen(key));
	zpointer value_tmp = (zpointer)malloc(value_size);
	memcpy(value_tmp, value_ptr, value_size);
    strncpy(key_tmp, key, strlen(key));
	stack->keys[stack->size] = key_tmp;
	stack->values[stack->size] = value_tmp;
	stack->size++;
	return true;
}

