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
#define DEBUGLOG_COMMON_LOG(fmt, ...)                                                                                            \
    { __android_log_print(ANDROID_LOG_INFO, "HookDEBUG", fmt, __VA_ARGS__); }
#else
#define DEBUGLOG_COMMON_LOG(fmt, ...)                                                                                            \
    { INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif