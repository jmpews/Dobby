#ifndef std_buffer_array_h
#define std_buffer_array_h

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _buffer_array_t {
    void *data;
    int size;
    int capacity;
} buffer_array_t;

buffer_array_t *buffer_array_create(int default_capacity);

void buffer_array_put(buffer_array_t *self, void *data, int length);

void buffer_array_clear(buffer_array_t *self);

void buffer_array_destory(buffer_array_t *self);

#ifdef __cplusplus
}
#endif

#endif
