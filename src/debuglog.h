#ifndef tools_h
#define tools_h

#include "hookzz.h"
#include "zkit.h"
#include "interceptor.h"

#include "SaitamaKit/CommonKit/log/log_kit.h"

typedef struct _DebugLogControler {
    bool is_enable_log;
    bool is_enable_debugbreak;
} DebugLogControler;

DebugLogControler *DebugLogControlerSharedInstance(void);
bool DebugLogControlerIsEnableLog();
bool DebugLogControlerIsEnableDebugbreak();

#if defined(__ANDROID__)
#include <android/log.h>
#define DEBUGLOG_COMMON_LOG(fmt, ...)                                                                                  \
    do { __android_log_print(ANDROID_LOG_INFO, "HookDEBUG", fmt, __VA_ARGS__); } while(0);
#else
#define DEBUGLOG_COMMON_LOG(fmt, ...)                                                                                  \
    do { INFO_LOG(fmt, __VA_ARGS__); } while(0);
#endif

void Log_TrampolineBuildForEnterTransfer(HookEntry *entry, CodeSlice *codeslice);
void Log_TrampolineBuildForEnter(HookEntry *entry);
void Log_TrampolineBuildForInvoke(HookEntry *entry, CodeSlice *codeslice);
void Log_TrampolineBuildForLeave(HookEntry *entry);

#endif