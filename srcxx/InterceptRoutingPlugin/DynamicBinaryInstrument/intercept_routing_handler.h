#ifndef HOOKZZ_DYNAMIC_BINARY_INSTRUMENT_INTERCEPT_ROUTING_HANDLER_H_
#define HOOKZZ_DYNAMIC_BINARY_INSTRUMENT_INTERCEPT_ROUTING_HANDLER_H_

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "Interceptor.h"
#include "hookzz_internal.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void instrument_routing_dispatch(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif