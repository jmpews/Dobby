//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef zzinfo_h
#define zzinfo_h

#include "hookzz.h"
#include "kitzz.h"

#include "zzdefs.h"

typedef struct _ZzInfo {
    bool g_enable_debug_flag;
} ZzInfo;

ZzInfo *ZzInfoObtain(void);
bool ZzIsEnableDebugMode();

#if defined(__ANDROID__)
#include <android/log.h>
#define ZzInfoLog(fmt, ...)                                                                                            \
    { __android_log_print(ANDROID_LOG_INFO, "zzinfo", fmt, __VA_ARGS__); }
#else
#define ZzInfoLog(fmt, ...)                                                                                            \
    { ZZ_INFO_LOG(fmt, __VA_ARGS__); }
#endif

#endif