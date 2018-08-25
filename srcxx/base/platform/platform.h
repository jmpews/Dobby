#ifndef ZZ_BASE_PLATFORM_PLATFORM_H_
#define ZZ_BASE_PLATFORM_PLATFORM_H_

class OS {
public:
    static int GetCurrentProcessId();

    static int GetCurrentThreadId();
     static void* Allocate(void* address, size_t size,
                                                size_t alignment,
                                                MemoryPermission access);

     static bool Free(void* address, const size_t size);

     static bool Release(void* address, size_t size);

     static bool SetPermissions(void* address, size_t size,
                                                     MemoryPermission access);
};

clas Thread {
        
};

#endif
