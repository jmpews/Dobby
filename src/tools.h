#ifndef tools_h
#define tools_h

#include "hookzz.h"
#include "zkit.h"

#include "tools.h"

typedef struct _HookZzDebugInfo {
    bool is_enable;
} HookZzDebugInfo;

HookZzDebugInfo *ZzInfoObtain(void);
bool HookZzDebugInfoIsEnable();

#if defined(__ANDROID__)
#include <android/log.h>
#define HookZzDebugInfoLog(fmt, ...)                                                                                   \
    { __android_log_print(ANDROID_LOG_INFO, "zzinfo", fmt, __VA_ARGS__); }
#else
#define HookZzDebugInfoLog(fmt, ...)                                                                                   \
    { ZZ_INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif