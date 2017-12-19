#include "CommonKit/log/log_kit.h"
#include "kitzz.h"

#define ZZ_KR_ERROR_LOG(kr)                                                                                            \
    do {                                                                                                               \
        ZZ_ERROR_LOG("kr = %d, reason: %s!", kr, mach_error_string(kr));                                               \
    } while (0)
