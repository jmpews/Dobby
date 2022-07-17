#pragma once

#include "dobby_internal.h"

extern "C" {
void instrument_routing_dispatch(HookEntry *entry, RegisterContext *ctx);
}