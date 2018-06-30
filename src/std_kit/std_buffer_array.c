#include "std_buffer_array.h"

buffer_array_t *buffer_array_create(int default_capacity) {
    if (default_capacity == 0) {
        default_capacity = 64;
    }

    unsigned char *data = (unsigned char *)malloc(default_capacity);

    buffer_array_t *buffer_array = (buffer_array_t *)malloc(sizeof(buffer_array_t));
    if (!buffer_array) {
        return NULL;
    }

    buffer_array->data     = data;
    buffer_array->size     = 0;
    buffer_array->capacity = default_capacity;
    return buffer_array;
}

void buffer_array_put(buffer_array_t *self, void *data, int length) {
    if (self->size + length > self->capacity) {
        unsigned char *data = (unsigned char *)realloc(self->data, self->capacity * 2);
        if (!data) {
            return;
        }
        self->capacity = self->capacity * 2;
        self->data     = data;
    }
    memcpy(self->data + self->size, data, length);
    self->size += length;
}

void buffer_array_clear(buffer_array_t *self) {
    self->size = 0;
    memset(self->data, 0, self->capacity);
    return;
}

void buffer_array_destory(buffer_array_t *self) {
    free(self->data);
    self->data = NULL;
    free(self);
    return;
}
