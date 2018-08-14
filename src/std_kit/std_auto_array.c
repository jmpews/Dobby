#include "std_auto_array.h"

auto_array_t *auto_array_create(int default_capacity, int granularity) {
  if (default_capacity == 0) {
    default_capacity = 64;
  }

  unsigned char *data = (unsigned char *)malloc(default_capacity);

  auto_array_t *auto_array = (auto_array_t *)malloc(sizeof(auto_array_t));
  if (!auto_array) {
    return NULL;
  }

  auto_array->data         = data;
  auto_array->size         = 0;
  auto_array->capacity     = default_capacity;
  auto_array->granule_size = granularity;
  return auto_array;
}

void auto_array_put(auto_array_t *self, void *data, int length) {
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

void auto_array_clear(auto_array_t *self) {
  self->size = 0;
  memset(self->data, 0, self->capacity);
  return;
}

void auto_array_destory(auto_array_t *self) {
  free(self->data);
  self->data = NULL;
  free(self);
  return;
}
