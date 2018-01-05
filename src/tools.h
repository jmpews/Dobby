#ifndef tools_h
#define tools_h

#include "hookzz.h"
#include "kitzz.h"

#include "tools.h"

typedef struct _ZzDebugInfo {
    bool g_enable_debug_flag;
} ZzDebugInfo;

ZzDebugInfo *ZzInfoObtain(void);
bool ZzIsEnableDebugMode();

#if defined(__ANDROID__)
#include <android/log.h>
#define ZzDebugInfoLog(fmt, ...)                                                                                       \
    { __android_log_print(ANDROID_LOG_INFO, "zzinfo", fmt, __VA_ARGS__); }
#else
#define ZzDebugInfoLog(fmt, ...)                                                                                       \
    { ZZ_INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif