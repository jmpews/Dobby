#ifndef KERNEL_OR_USER_H_
#define KERNEL_OR_USER_H_

#if defined(KERNELMODE)

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#else

#include <string.h>
#include <stdarg.h>

#endif

#endif
