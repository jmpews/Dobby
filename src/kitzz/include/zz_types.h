#ifndef kitzz_zz_types_h
#define kitzz_zz_types_h

#include <stdbool.h>
#include <stdint.h>

// for bool type
#if !defined(FALSE) && !defined(TRUE)
#if defined(false) && defined(true)
#define FALSE false
#define TRUE true
#else
#define FALSE 0
#define TRUE 1
#endif
#endif

typedef unsigned long zz_addr_t;
typedef void *zz_ptr_t;
typedef unsigned long zz_size_t;
typedef unsigned int zz_uint_t;

typedef uint64_t zuint64_t;
typedef uint32_t zuint32_t;
typedef uint16_t zuint16_t;
typedef uint8_t zuint8_t;

typedef int64_t zint64_t;
typedef int32_t zint32_t;
typedef int16_t zint16_t;
typedef int8_t zint8_t;

#endif
