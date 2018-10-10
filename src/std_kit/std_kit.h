#ifndef std_kit_std_kit_h
#define std_kit_std_kit_h

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "std_log.h"
#include "std_macros.h"

/* malloc with 0 and NULL check */
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
void *safe_malloc(size_t size);
#ifdef __cplusplus
}
#endif //__cplusplus

/* malloc macro */
#define SAFE_MALLOC_TYPE(TYPE) (TYPE *)safe_malloc(sizeof(TYPE));

/* safe free*/
#define SAFE_FREE(obj)                                                                                                 \
  do {                                                                                                                 \
    free(obj);                                                                                                         \
    obj = NULL;                                                                                                        \
  } while (0);

#include <errno.h>
#if ENABLE_COLOR_LOG
#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"
#else
#define RED ""
#define GRN ""
#define YEL ""
#define BLU ""
#define MAG ""
#define CYN ""
#define WHT ""
#define RESET ""
#endif

#define ENABLE_PRINT_ERROR_STRING 0

#define ERROR_LOG_ERRNO()                                                                                              \
  do {                                                                                                                 \
    fprintf(stderr, "======= ERRNO [%d] STRING ======= \n", errno);                                                    \
    perror((const char *)strerror(errno));                                                                             \
  } while (0);

#define ERROR_LOG(fmt, ...)                                                                                            \
  do {                                                                                                                 \
    fprintf(stderr,                                                                                                    \
            RED "[!] "                                                                                                 \
                "%s:%d:%s(): " fmt RESET "\n",                                                                         \
            __FILE__, __LINE__, __func__, __VA_ARGS__);                                                                \
  } while (0)

#define ERROR_LOG_STR(MSG) ERROR_LOG("%s", MSG)

#define ERROR_LOG_LINE() ERROR_LOG_STR(">>> ERROR <<<")

#define XCHECK(repr)                                                                                                   \
  do {                                                                                                                 \
    if (repr) { /*pass*/                                                                                               \
    } else {                                                                                                           \
      ERROR_LOG_LINE();                                                                                                \
    }                                                                                                                  \
  } while (0);

#endif