#ifndef tools_h
#define tools_h

#include "hookzz.h"
#include "zkit.h"

typedef struct _DebugLogControler {
    bool is_enable_log;
    bool is_enable_debugbreak;
} DebugLogControler;

DebugLogControler *DebugLogControlerSharedInstance(void);
bool DebugLogControlerIsEnableLog();
bool DebugLogControlerIsEnableDebugbreak();

#if defined(__ANDROID__)
#include <android/log.h>
#define DEBUG_LOG(fmt, ...)                                                                                           \
    { __android_log_print(ANDROID_LOG_INFO, "HookDEBUG_LOG", fmt, __VA_ARGS__); }
#else
#define DEBUG_LOG(fmt, ...)                                                                                           \
    { ZZ_INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif