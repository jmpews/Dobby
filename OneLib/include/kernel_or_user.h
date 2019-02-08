#ifndef ONELIB_KERNEL_OR_USER_H_
#define ONELIB_KERNEL_OR_USER_H_

#ifdef KERNELMODE

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#else

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#endif

#endif
