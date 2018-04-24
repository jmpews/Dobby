#include "CommonKit/log/log_kit.h"
#include "zkit.h"

#define ZZ_KR_ERROR_LOG(kr)                                                                                            \
    do {                                                                                                               \
        ERROR_LOG("kr = %d, reason: %s!", kr, mach_error_string(kr));                                               \
    } while (0)
