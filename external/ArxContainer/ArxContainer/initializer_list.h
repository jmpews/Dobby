#pragma once

#ifndef ARX_TYPE_TRAITS_INITIALIZER_H
#define ARX_TYPE_TRAITS_INITIALIZER_H

// Initializer_list *must* be defined in std, so take extra care to only
// define it when <initializer_list> is really not available (e.g.
// ArduinoSTL is C++98 but *does* define <initializer_list>) and not
// already defined (e.g. by ArxContainer).
#if ARX_SYSTEM_HAS_INCLUDE(<initializer_list>)
#include <initializer_list>
#else
namespace std {
template <class T>
class initializer_list {
private:
    const T* array;
    size_t len;
    initializer_list(const T* a, size_t l)
    : array(a), len(l) {}

public:
    initializer_list()
    : array(nullptr), len(0) {}
    size_t size() const { return len; }
    const T* begin() const { return array; }
    const T* end() const { return array + len; }
};
}  // namespace std
#endif

#endif  // ARX_TYPE_TRAITS_INITIALIZER_LIST_H
