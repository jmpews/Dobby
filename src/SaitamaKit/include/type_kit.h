#ifndef type_kit_h
#define type_kit_h

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

#endif
