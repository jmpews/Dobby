#ifndef zzdeps_posix_thread_utils_h
#define zzdeps_posix_thread_utils_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <pthread.h>

#include "../zz.h"

typedef struct _ThreadLocalKey {
    pthread_key_t key;
} ThreadLocalKey;

typedef struct _ThreadLocalKeyList {
    zsize size;
    zsize capacity;
    ThreadLocalKey **keys;
} ThreadLocalKeyList;

void zz_posix_thread_initialize_thread_local_key_list();

zpointer zz_posix_thread_new_thread_local_key_ptr();

zpointer zz_posix_thread_get_current_thread_data(zpointer key_ptr);

zbool zz_posix_thread_set_current_thread_data(zpointer key_ptr, zpointer data);

long zz_posix_get_current_thread_id();

#endif