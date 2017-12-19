#include "objc/oobjc.h"

namespace objc {
    class_rw_t *data(uintptr_t bits) {
        return (struct class_rw_t *) (bits & FAST_DATA_MASK);
    }


    bool hasArray(x_array_t *t) { return t->arrayAndFlag & 1; }

    array_t *array(x_array_t *t) { return (array_t *) (t->arrayAndFlag & ~1); }

    List **arrayList(x_array_t *t) {
        if (hasArray(t)) {
            return array(t)->lists;
        } else {
            return &(t->list);
        }
    }


// objc-internal.h
// #if TARGET_OS_OSX && __x86_64__
#if __x86_64__
    // 64-bit Mac - tag bit is LSB
#   define OBJC_MSB_TAGGED_POINTERS 0
#else
    // Everything else - tag bit is MSB
#   define OBJC_MSB_TAGGED_POINTERS 1
#endif

#if OBJC_MSB_TAGGED_POINTERS
#   define _OBJC_TAG_MASK (1ULL<<63)
#else
#   define _OBJC_TAG_MASK 1
#endif

    bool _objc_isTaggedPointer(const void *ptr) {

        return ((intptr_t) ptr & _OBJC_TAG_MASK) == _OBJC_TAG_MASK;
    }
}
