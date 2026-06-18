#pragma once

enum MemoryPermission {
    kNoAccess,
    kRead = 1,
    kWrite = 2,
    kExecute = 4,
    kReadWrite = kRead | kWrite,
    kReadExecute = kRead | kExecute,
    kReadWriteExecute = kRead | kWrite | kExecute,
};

class OSMemory {
public:
    static int PageSize();

    static void *Allocate(size_t size, MemoryPermission access);

    static void *Allocate(size_t size, MemoryPermission access, void *fixed_addr);

    static bool Free(void *address, size_t size);

    static bool Release(void *address, size_t size);

    static bool SetPermission(void *address, size_t size, MemoryPermission access);
};