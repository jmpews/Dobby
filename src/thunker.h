#ifndef bridge_h
#define bridge_h

#include "hookzz.h"
#include "zkit.h"

#include "interceptor.h"

struct _InterceptorBackend;
void BridgeBuildAll(struct _InterceptorBackend *backend);

#endif
