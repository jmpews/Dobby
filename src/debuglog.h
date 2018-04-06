#ifndef tools_h
#define tools_h

#include "hookzz.h"
#include "zkit.h"

#include "tools.h"

typedef struct _ZzDebugLogControler {
    bool is_enable_log;
    bool is_enable_debugbreak;
} ZzDebugLogControler;

ZzDebugLogControler *ZzDebugLogControlerSharedInstance(void);
bool ZzIsEnableLog();
bool ZzIsEnableDebugbreak();

#if defined(__ANDROID__)
#include <android/log.h>
#define ZzDebugLog(fmt, ...)                                                                                           \
    { __android_log_print(ANDROID_LOG_INFO, "HookZzDebugLog", fmt, __VA_ARGS__); }
#else
#define ZzDebugLog(fmt, ...)                                                                                           \
    { ZZ_INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif