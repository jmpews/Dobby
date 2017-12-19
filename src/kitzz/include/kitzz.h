#ifndef kitzz_h
#define kitzz_h

#define PROGRAM_NAME "kitzz"
#define PROGRAM_VER "1.0.0"
#define PROGRAM_AUTHOR "jmpews@gmail.com"

#include "zz_macros.h"
#include "zz_types.h"

#define GLOBAL_DEBUG FALSE
#define GLOBAL_DEBUG_LOG FALSE
#define GLOBAL_INFO_LOG FALSE

#ifdef GLOBAL_DEBUG
#include "CommonKit/debug/debug_kit.h"
#include "CommonKit/debug/debugbreak.h"
#endif

// clang-format off
// http://nadeausoftware.com/articles/2012/01/c_c_tip_how_use_compiler_predefined_macros_detect_operating_system
// https://sourceforge.net/p/predef/wiki/OperatingSystems/
#ifdef _WIN32
   //define something for Windows (32-bit and 64-bit, this part is common)
   #ifdef _WIN64
      //define something for Windows (64-bit only)
   #else
      //define something for Windows (32-bit only)
   #endif
#elif __APPLE__
    #if TARGET_IPHONE_SIMULATOR
         // iOS Simulator
    #elif TARGET_OS_IPHONE
        // iOS device
    #elif TARGET_OS_MAC
        // Other kinds of Mac OS
    #else
    #endif
#elif __ANDROID__
    // android
#elif __linux__
    // linux
#elif __unix__ // all unices not caught above
    // Unix
#elif defined(_POSIX_VERSION)
    // POSIX
#else
    #error "Unknown compiler"
#endif

#endif