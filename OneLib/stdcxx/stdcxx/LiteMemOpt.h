#ifndef LITE_MEM_OPT_H_
#define LITE_MEM_OPT_H_

extern void *memcpy(void *, const void *, int);

extern void bzero(void *, int);

extern void *memset(void *, int, int);

class LiteMemOpt {
public:
  static void *alloc(int size);

  static void free(void *address, int size);

public:
#if 0
  static void (*copy_)(void *, void *, int);

  static void *(*alloc_)(int);

  static void (*free_)(void *, int);
#endif
};

#endif
