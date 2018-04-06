#ifndef memory_kit_h
#define memory_kit_h

typedef struct _ZMemoryLayout {
    int size;
    struct {
        int flags;
        void *start;
        void *end;
    } mem[4096];
} ZMemoryLayout;

char *ZmmReadString(const char *address);

#endif