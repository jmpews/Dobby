#pragma once

#ifndef ARX_TYPE_TRAITS_HAS_LIBSTDCPLUSPLUS_H
#define ARX_TYPE_TRAITS_HAS_LIBSTDCPLUSPLUS_H

#if !defined(ARX_HAVE_LIBSTDCPLUSPLUS)
    #if ARX_SYSTEM_HAS_INCLUDE(<cstdlib>)
        #include <cstdlib>
        #if defined(__GLIBCXX__) || defined(_LIBCPP_VERSION)
            // For gcc's libstdc++ and clang's libc++, assume that
            // __cplusplus tells us what the standard includes support
            #define ARX_HAVE_LIBSTDCPLUSPLUS __cplusplus
        #elif defined(__UCLIBCXX_MAJOR__)
            // For uclibc++, assume C++98 support only.
            #define ARX_HAVE_LIBSTDCPLUSPLUS 199711L
        #else
            #error "Unknown C++ library found, please report a bug against the ArxTypeTraits library about this."
        #endif
    #else
        // Assume no standard library is available at all (e.g. on AVR)
        #define ARX_HAVE_LIBSTDCPLUSPLUS 0
    #endif
#endif

#endif // ARX_TYPE_TRAITS_HAS_LIBSTDCPLUSPLUS_H
