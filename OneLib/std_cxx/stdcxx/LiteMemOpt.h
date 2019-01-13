
#ifndef LITE_MEM_OPT_H_
#define LITE_MEM_OPT_H_

class LiteLiteMemOpt {
  static inline void read(void *address, void *data, int length) {
    LiteMemOpt::copy(data, address, length);
    return;
  }

  static inline void write(void *address, void *data, int length) {
    LiteMemOpt::copy(address, data, length);
    return;
  }

#ifdef KERNELMODE
#error "Unimplemented in KernelMode."
#else
  static inline void copy(void *dest, void *src, int length) {
    memcpy(dest, src, length);
    return;
  }

  static inline void *alloc(int size) {
    void *result = malloc(size);
    return result;
  }
#endif
};

#endif