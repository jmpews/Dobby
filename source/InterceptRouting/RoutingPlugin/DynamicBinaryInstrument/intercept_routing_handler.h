#ifndef INTERCEPT_ROUTING_HANDLER_H
#define INTERCEPT_ROUTING_HANDLER_H

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "Interceptor.h"
#include "dobby_internal.h"

extern "C" {
void instrument_routing_dispatch(RegisterContext *ctx, ClosureTrampolineEntry *entry);
}

#endif