#ifndef objc_h
#define objc_h

namespace objc
{

#include <stdint.h>

#define SUPPORT_PACKED_ISA 1

struct objc_class;
struct objc_object;

typedef struct objc_class *Class;
typedef struct objc_object *id;

union isa_t {
    isa_t() {}

    isa_t(uintptr_t value) : bits(value) {}

    Class cls;
    uintptr_t bits;

#if SUPPORT_PACKED_ISA

// extra_rc must be the MSB-most field (so it matches carry/overflow flags)
// nonpointer must be the LSB (fixme or get rid of it)
// shiftcls must occupy the same bits that a real class pointer would
// bits + RC_ONE is equivalent to extra_rc + 1
// RC_HALF is the high bit of extra_rc (i.e. half of its range)

// future expansion:
// uintptr_t fast_rr : 1;     // no r/r overrides
// uintptr_t lock : 2;        // lock for atomic property, @synch
// uintptr_t extraBytes : 1;  // allocated with extra bytes

#if __arm64__
#define ISA_MASK 0x0000000ffffffff8ULL
#define ISA_MAGIC_MASK 0x000003f000000001ULL
#define ISA_MAGIC_VALUE 0x000001a000000001ULL
    struct
    {
        uintptr_t nonpointer : 1;
        uintptr_t has_assoc : 1;
        uintptr_t has_cxx_dtor : 1;
        uintptr_t shiftcls : 33; // MACH_VM_MAX_ADDRESS 0x1000000000
        uintptr_t magic : 6;
        uintptr_t weakly_referenced : 1;
        uintptr_t deallocating : 1;
        uintptr_t has_sidetable_rc : 1;
        uintptr_t extra_rc : 19;
#define RC_ONE (1ULL << 45)
#define RC_HALF (1ULL << 18)
    };

#elif __x86_64__
#define ISA_MASK 0x00007ffffffffff8ULL
#define ISA_MAGIC_MASK 0x001f800000000001ULL
#define ISA_MAGIC_VALUE 0x001d800000000001ULL
    struct
    {
        uintptr_t nonpointer : 1;
        uintptr_t has_assoc : 1;
        uintptr_t has_cxx_dtor : 1;
        uintptr_t shiftcls : 44; // MACH_VM_MAX_ADDRESS 0x7fffffe00000
        uintptr_t magic : 6;
        uintptr_t weakly_referenced : 1;
        uintptr_t deallocating : 1;
        uintptr_t has_sidetable_rc : 1;
        uintptr_t extra_rc : 8;
#define RC_ONE (1ULL << 56)
#define RC_HALF (1ULL << 7)
    };

#else
#error unknown architecture for packed isa
#endif

// SUPPORT_PACKED_ISA
#endif

#if SUPPORT_INDEXED_ISA

#if __ARM_ARCH_7K__ >= 2

#define ISA_INDEX_IS_NPI 1
#define ISA_INDEX_MASK 0x0001FFFC
#define ISA_INDEX_SHIFT 2
#define ISA_INDEX_BITS 15
#define ISA_INDEX_COUNT (1 << ISA_INDEX_BITS)
#define ISA_INDEX_MAGIC_MASK 0x001E0001
#define ISA_INDEX_MAGIC_VALUE 0x001C0001
    struct
    {
        uintptr_t nonpointer : 1;
        uintptr_t has_assoc : 1;
        uintptr_t indexcls : 15;
        uintptr_t magic : 4;
        uintptr_t has_cxx_dtor : 1;
        uintptr_t weakly_referenced : 1;
        uintptr_t deallocating : 1;
        uintptr_t has_sidetable_rc : 1;
        uintptr_t extra_rc : 7;
#define RC_ONE (1ULL << 25)
#define RC_HALF (1ULL << 6)
    };

#else
#error unknown architecture for indexed isa
#endif

// SUPPORT_INDEXED_ISA
#endif
};

struct objc_object
{
    isa_t isa;
};

// --------------------------------------------------------------------------------------------------------------------

#define FAST_DATA_MASK 0x00007ffffffffff8UL
#define RW_REALIZED (1 << 31)
#define RW_REALIZING (1 << 19)

typedef void protocol_list_t;
typedef void property_list_t;
struct ivar_t
{
#if __x86_64__
// *offset was originally 64-bit on some x86_64 platforms.
// We read and write only 32 bits of it.
// Some metadata provides all 64 bits. This is harmless for unsigned
// little-endian values.
// Some code uses all 64 bits. class_addIvar() over-allocates the
// offset for their benefit.
#endif
    int32_t *offset;
    const char *name;
    const char *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
};

typedef struct
{
    uint32_t entsizeAndFlags;
    uint32_t count;
    struct ivar_t first;
} ivar_list_t;

struct method_t
{
    void *name;
    const char *types;
    void *imp;
};
typedef struct
{
    uint32_t entsizeAndFlags;
    uint32_t count;
    struct method_t first;
} method_list_t;

#if __LP64__
typedef uint32_t mask_t; // x86_64 & arm64 asm are less efficient with 16-bits
#else
typedef uint16_t mask_t;
#endif

struct class_ro_t
{
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
#ifdef __LP64__
    uint32_t reserved;
#endif

    const uint8_t *ivarLayout;

    const char *name;
    method_list_t *baseMethodList;
    protocol_list_t *baseProtocols;
    const ivar_list_t *ivars;

    const uint8_t *weakIvarLayout;
    property_list_t *baseProperties;
};

// important！！！ if write use C++, 'template' may be the better chooise.
typedef void List;

struct array_t
{
    uint32_t count;
    List *lists[0];
};

typedef struct list_array_tt
{
    union {
        List *list;
        uintptr_t arrayAndFlag;
    };
} x_array_t;

// list_array_tt method
bool hasArray(x_array_t *t);

array_t *array(x_array_t *t);

List **arrayList(x_array_t *t);

struct class_rw_t
{
    // Be warned that Symbolication knows the layout of this structure.
    uint32_t flags;
    uint32_t version;

    const class_ro_t *ro;

    x_array_t methods;
    x_array_t properties;
    x_array_t protocols;

    Class firstSubclass;
    Class nextSiblingClass;

    char *demangledName;

#if SUPPORT_INDEXED_ISA
    uint32_t index;
#endif
};

struct objc_class
{
    Class isa; // metaclass
    Class superclass; // superclas
    // struct bucket_t *
    void *_buckets; // cache
    mask_t _mask; // vtable
    mask_t _occupied; // vtable
    uintptr_t bits; // data
};

class_rw_t *data(uintptr_t bits);

bool _objc_isTaggedPointer(const void *ptr);
}
#endif
