#ifndef LITE_MEM_OPT_H_
#define LITE_MEM_OPT_H_

class LiteMemOpt {
public:
  static void copy(void *dest, void *src, int length);

  static void *alloc(int size);

  static void free(void *address, int size);

  static void read(void *address, void *data, int length);

  static void write(void *address, void *data, int length);
};

#endif
