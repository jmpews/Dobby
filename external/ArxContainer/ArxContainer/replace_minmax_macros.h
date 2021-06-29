#pragma once

#ifndef ARX_TYPE_TRAITS_REPLACE_MINMAX_MACROS_H
#define ARX_TYPE_TRAITS_REPLACE_MINMAX_MACROS_H

// Make sure Arduino.h is actually included, since otherwise it might be
// included later and break *uses* of the min/max methods, rather than
// the declarations of it.
#ifdef ARDUINO
    #include <Arduino.h>
#endif

// These macros are defined by Arduino.h on some platforms, and conflict
// with min/max methods defined or included by ArxTypeTraits, so replace
// them with macros here.
#ifdef max
    #undef max
    template <typename T1, typename T2>
    constexpr auto max(T1 x, T2 y)
    -> decltype(x + y)
    {
        return (x > y) ? x : y;
    }
#endif
#ifdef min
    #undef min
    template <typename T1, typename T2>
    constexpr auto min(T1 x, T2 y)
    -> decltype(x + y)
    {
        return (x < y) ? x : y;
    }
#endif

#endif // ARX_TYPE_TRAITS_REPLACE_MINMAX_MACROS_H
