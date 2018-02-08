
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

#include "kitzz.h"

typedef struct _ThreadLocalKey {
    pthread_key_t key;
} ThreadLocalKey;

typedef struct _ThreadLocalKeyList {
    zz_size_t size;
    zz_size_t capacity;
    ThreadLocalKey **keys;
} ThreadLocalKeyList;

void zz_posix_thread_initialize_thread_local_key_list();

zz_ptr_t zz_posix_thread_new_thread_local_key_ptr();

bool zz_posix_thread_free_thread_local_key(zz_ptr_t key_ptr);

zz_ptr_t zz_posix_thread_get_current_thread_data(zz_ptr_t key_ptr);

bool zz_posix_thread_set_current_thread_data(zz_ptr_t key_ptr, zz_ptr_t data);

long zz_posix_get_current_thread_id();
