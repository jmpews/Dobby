#include "common_memory_kit.h"

#if __APPLE__
#include "DarwinKit/MemoryKit/darwin_memory_kit.h"
#include "PosixKit/memory/posix_memory_kit.h"
#elif __ANDROID__ || __linux__
#include "LinuxKit/memory/linux_memory_kit.h"
#include "PosixKit/memory/posix_memory_kit.h"
#endif

char *ZmmReadString(const char *address) { return zz_vm_read_string(address); }

char *ZmmAllocateMemoryPage(size_t nPages) {
    return NULL;
}