#ifndef RUNTIME_PLATFORM_GLOBALS_H_
#define RUNTIME_PLATFORM_GLOBALS_H_

#if defined(_WIN32)
// Cut down on the amount of stuff that gets included via windows.h.
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#if !defined(NOMINMAX)
#define NOMINMAX
#endif

#if !defined(NOKERNEL)
#define NOKERNEL
#endif

#if !defined(NOSERVICE)
#define NOSERVICE
#endif

#if !defined(NOSOUND)
#define NOSOUND
#endif

#if !defined(NOMCX)
#define NOMCX
#endif

#if !defined(UNICODE)
#define _UNICODE
#define UNICODE
#endif

#include <Rpc.h>
#include <VersionHelpers.h>
#include <intrin.h>
#include <shellapi.h>
#include <windows.h>
#include <winsock2.h>
#endif // defined(_WIN32)

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#endif // !defined(_WIN32)

// =====

// Target OS detection.
// for more information on predefined macros:
//   - http://msdn.microsoft.com/en-us/library/b0084kay.aspx
//   - with gcc, run: "echo | gcc -E -dM -"
#if defined(__ANDROID__)

// Check for Android first, to determine its difference from Linux.
#define HOST_OS_ANDROID 1

#elif defined(__linux__) || defined(__FreeBSD__)

// Generic Linux.
#define HOST_OS_LINUX 1

#elif defined(__APPLE__)

// Define the flavor of Mac OS we are running on.
#include <TargetConditionals.h>
// TODO(iposva): Rename HOST_OS_MACOS to HOST_OS_MAC to inherit
// the value defined in TargetConditionals.h
#define HOST_OS_MACOS 1
#if TARGET_OS_IPHONE
#define HOST_OS_IOS 1
#endif

#elif defined(_WIN32)

// Windows, both 32- and 64-bit, regardless of the check for _WIN32.
#define HOST_OS_WINDOWS 1

#endif
#endif