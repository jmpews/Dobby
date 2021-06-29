#pragma once

#ifndef ARX_TYPE_TRAITS_HAS_INCLUDE_H
#define ARX_TYPE_TRAITS_HAS_INCLUDE_H

    // Check whether __has_include is available, but also check the GCC
    // version (__has_include was introduced in gcc 5) to catch
    // environments (such as ESP8266) where gcc is old, but some system
    // header provides a fake __has_include. We also need to check
    // against __clang__ here, since clang pretends to be GCC
    // 4.something and would otherwise be detected incorrectly here...
    #if !defined(__has_include) || defined(__GNUC__) && __GNUC__ < 5 && !defined(__clang__)
        #if defined(ARDUINO_ARCH_ESP8266)
            // ESP8266 does not have a working __has_include, but we
            // know it does have a working libstdc++ with all the
            // headers we care about, so provide a fake has_include
            #define ARX_SYSTEM_HAS_INCLUDE(x) 1
        #elif defined(ARDUINO_SAM_DUE)
            // Arduino DUE's GCC version is 4.8.3 (GCC < 5.0).
            // If libstdc++ is used, std::function causes error
            // so currently we disable libstdc++ and use ArxTypeTraits
            #define ARX_SYSTEM_HAS_INCLUDE(x) 0
        #else
            #error "Compiler does not support __has_include, please report a bug against the ArxTypeTraits library about this."
        #endif
    #else
        #define ARX_SYSTEM_HAS_INCLUDE(x) __has_include(x)
    #endif

#endif // ARX_TYPE_TRAITS_HAS_INCLUDE_H
