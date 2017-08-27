/**
 *    Copyright 2017 jmpews
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef hook_zz_h
#define hook_zz_h

#include <stdint.h>
#include <stdbool.h>

#ifndef zz_h
#define zz_h

// Created by jmpews on 2017/5/3.
//
#define PROGRAM_NAME "zz"
#define PROGRAM_VER "1.0.0"
#define PROGRAM_AUTHOR "jmpews@gmail.com"

#include <stdint.h>


// --- custom type ---

// 1. zpointer and zaddr is different

typedef void *zpointer;
typedef unsigned long zsize;
typedef unsigned long zaddr;
typedef unsigned long zuint;
typedef long zint;
typedef unsigned char zbyte;

#ifndef bool
typedef uint8_t bool;
#define false 0
#define true 1
#endif

// --- log configuration ---

#define GLOBAL_DEBUG 0
#define GLOBAL_INFO 1
#define SYSLOG 0
#define COLOR_LOG 0

#if (COLOR_LOG)
#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"
#else
#define RED ""
#define GRN ""
#define YEL ""
#define BLU ""
#define MAG ""
#define CYN ""
#define WHT ""
#define RESET ""
#endif

#include <stdio.h>
#include <sys/syslog.h>

// Important!!!
// STDERR before STDOUT, because sync

#if (SYSLOG)
#define Xinfo(fmt, ...)                                                        \
  do {                                                                         \
    if (GLOBAL_INFO)                                                           \
      syslog(LOG_WARNING, RESET fmt, __VA_ARGS__);                             \
  } while (0)
#define Sinfo(MSG) Xinfo("%s", MSG)
#define Xdebug(fmt, ...)                                                       \
  do {                                                                         \
    if (GLOBAL_DEBUG)                                                          \
      syslog(LOG_WARNING, RESET fmt, __VA_ARGS__);                               \
  } while (0)
#define Sdebug(MSG) Xdebug("%s", MSG)
#define Xerror(fmt, ...)                                                       \
  do {                                                                         \
    syslog(LOG_DEBUG,                                                          \
           RED "[!] "                                                          \
               "%s:%d:%s(): " fmt RESET "\n",                                  \
           __FILE__, __LINE__, __func__, __VA_ARGS__);                         \
  } while (0)

#define Serror(MSG) Xerror("%s", MSG)
#else
#define Xinfo(fmt, ...)                                                        \
  do {                                                                         \
    if (GLOBAL_INFO)                                                           \
      fprintf(stdout, RESET fmt "\n", __VA_ARGS__);                            \
  } while (0)
#define Sinfo(MSG) Xinfo("%s", MSG)

#define Xdebug(fmt, ...)                                                       \
  do {                                                                         \
    if (GLOBAL_DEBUG)                                                          \
      fprintf(stdout, RESET fmt "\n", __VA_ARGS__);                            \
  } while (0)
#define Sdebug(MSG) Xdebug("%s", MSG)
#define Xerror(fmt, ...)                                                       \
  do {                                                                         \
    fprintf(stderr,                                                            \
            RED "[!] "                                                         \
                "%s:%d:%s(): " fmt RESET "\n",                                 \
            __FILE__, __LINE__, __func__, __VA_ARGS__);                        \
  } while (0)

#define Serror(MSG) Xerror("%s", MSG)
#endif
#endif

#if defined (__aarch64__)
typedef union FPReg_ {
    __int128_t q;
    struct {
        double d1; // Holds the double (LSB).
        double d2;
    } d;
    struct {
        float f1; // Holds the float (LSB).
        float f2;
        float f3;
        float f4;
    } f;
} FPReg;

// just ref how to backup/restore registers
typedef struct _RegState {
    uint64_t pc;
    uint64_t sp;

    union {
        uint64_t x[29];
        struct {
            uint64_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28;
        } regs;
    } general;

    uint64_t fp;
    uint64_t lr;

    union {
        FPReg q[8];
        FPReg q0,q1,q2,q3,q4,q5,q6,q7;
    } floating;
} RegState;
#elif defined(__x86_64__)
#endif


typedef enum _ZZSTATUS {
    ZZ_UNKOWN = -1,
    ZZ_DONE = 0,
    ZZ_SUCCESS,
    ZZ_FAILED,
    ZZ_DONE_HOOK,
    ZZ_DONE_INIT,
    ZZ_DONE_ENABLE,
    ZZ_ALREADY_HOOK,
    ZZ_ALREADY_INIT,
    ZZ_ALREADY_ENABLED,
    ZZ_NEED_INIT,
    ZZ_NO_BUILD_HOOK
} ZZSTATUS;


typedef struct _CallStack
{
    long call_id;
	zsize size;
} CallStack;

typedef struct _ThreadStack
{
    long thread_id;
	zsize size;
} ThreadStack;


typedef void (*PRECALL)(RegState *rs, ThreadStack *threadstack, CallStack *callstack);
typedef void (*POSTCALL)(RegState *rs, ThreadStack *threadstack, CallStack *callstack);
typedef void (*HALFCALL)(RegState *rs, ThreadStack *threadstack, CallStack *callstack);

zpointer ZzGetCallStackData(zpointer stack_ptr, char *key);
bool ZzSetCallStackData(zpointer stack_ptr, char *key, zpointer value_ptr, zsize value_size);

#define STACK_CHECK_KEY(stack, key) (bool)ZzGetCallStackData(stack, key)
#define STACK_GET(stack, key, type) *(type *)ZzGetCallStackData(stack, key)
#define STACK_SET(stack, key, value, type) ZzSetCallStackData(stack, key, &(value), sizeof(type))

ZZSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_ptr, zpointer *origin_ptr, PRECALL pre_call_ptr,
    POSTCALL post_call_ptr);
ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, PRECALL pre_call_ptr, HALFCALL half_call_ptr);
ZZSTATUS ZzEnableHook(zpointer target_ptr);
ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size);

#endif