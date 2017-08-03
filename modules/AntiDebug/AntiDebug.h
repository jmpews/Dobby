#include <sys/types.h>

typedef void *zpointer;
typedef unsigned long zsize;
typedef unsigned long zaddr;
typedef unsigned long zuint;
typedef long zint;
typedef unsigned char zbyte;
#ifndef NULL
#define NULL 0
#endif // !1NULL


char *CheckDyliblist[] = {
        "Substrate.dylib",
        NULL
};

char *CheckFileList[] = {
        "/Applications/Cydia.app",
        NULL
};