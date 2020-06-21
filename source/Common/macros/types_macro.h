
#ifndef TYPES_HEADER_H
#define TYPES_HEADER_H

#include <stdint.h>

#ifndef __addr_t_defined
#define __addr_t_defined
typedef unsigned long addr_t;
#endif

#ifndef __byte_defined
#define __byte_defined
typedef unsigned char byte;
#endif

#ifndef __uint_defined
#define __uint_defined
typedef unsigned int uint;
#endif

#ifndef __word_defined
#define __word_defined
typedef short word;
#endif

#ifndef __dword_defined
#define __dword_defined
typedef int dword;
#endif

#ifndef NULL
#define NULL 0
#endif

#endif