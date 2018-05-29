#ifndef invocation_h
#define invocation_h

#include "hookzz.h"
#include "zkit.h"

#include "interceptor.h"
#include "writer.h"

void context_begin_invocation(RegState *rs, HookEntry *entry, void *nextHop, void *retAddr);

void context_end_invocation(RegState *rs, HookEntry *entry, void *nextHop);

void dynamic_binary_instrumentation_invocation(RegState *rs, HookEntry *entry, void *nextHop);

#endif