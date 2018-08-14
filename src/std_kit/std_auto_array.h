#ifndef std_auto_array_h
#define std_auto_array_h

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _auto_array_t {
  void *data;
  int size;
  int capacity;
  int granule_size;
} auto_array_t;

auto_array_t *auto_array_create(int default_capacity);

void auto_array_put(auto_array_t *self, void *data, int length);

void auto_array_clear(auto_array_t *self);

void auto_array_destory(auto_array_t *self);

#ifdef __cplusplus
}
#endif

#endif
