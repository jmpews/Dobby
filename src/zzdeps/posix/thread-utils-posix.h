#ifndef zzdeps_posix_thread_utils_h
#define zzdeps_posix_thread_utils_h

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

#include "../zz.h"

typedef struct _ZzThreadLocalKey {
    zsize size;
    zsize capacity;
    pthread_key_t *thread_local_keys;
} ZzThreadLocalKey;

void zz_thread_initialize_thread_local_keys();
zpointer zz_thread_new_thread_local_key();
zpointer zz_thread_get_current_thread_data(zpointer key_ptr);
int zz_thread_set_current_thread_data(zpointer key_ptr, zpointer data);

#endif