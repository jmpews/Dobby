#include "thread-utils-posix.h"

static ZzThreadLocalKey *g_thread_local_key;

void zz_thread_initialize_thread_local_keys() {
    if(!g_thread_local_key) {
        ZzThreadLocalKey *global_thread_local_key = (ZzThreadLocalKey *)malloc(sizeof(ZzThreadLocalKey));
        global_thread_local_key->capacity = 4;
        pthread_key_t *thread_local_keys = (pthread_key_t *)malloc(sizeof(pthread_key_t));
        if(!thread_local_keys)
            return;
        global_thread_local_key->thread_local_keys = thread_local_keys;
        global_thread_local_key->size = 0;
        g_thread_local_key = global_thread_local_key;
    }
}

zpointer zz_thread_new_thread_local_key() {
    if(!g_thread_local_key) {
        zz_thread_initialize_thread_local_keys();
    }
    ZzThreadLocalKey *g_keys= g_thread_local_key;
	if (g_keys->size >= g_keys->capacity)
	{
		pthread_key_t *thread_local_keys = (pthread_key_t *)realloc(g_keys->thread_local_keys, sizeof(pthread_key_t) * (g_keys->capacity) * 2);
		if(!thread_local_keys)
			return false;
        g_keys->thread_local_keys = thread_local_keys;
        g_keys->capacity = g_keys->capacity * 2;
	}

    pthread_key_t *key_ptr = &(g_keys->thread_local_keys[g_keys->size]);
    pthread_key_create(key_ptr, NULL);
	g_keys->size++;
	return key_ptr;
}

zpointer zz_thread_get_current_thread_data(zpointer key_ptr) {
    ZzThreadLocalKey *g_keys= g_thread_local_key;
    pthread_key_t key = *(pthread_key_t *)key_ptr;
    for (zsize i = 0; i < g_keys->size; i++)
    {
        if(g_keys->thread_local_keys[i] == key)
            return (zpointer)pthread_getspecific(g_keys->thread_local_keys[i]);
    }
    return NULL;
}

int zz_thread_set_current_thread_data(zpointer key_ptr, zpointer data) {
    ZzThreadLocalKey *g_keys= g_thread_local_key;
    pthread_key_t key = *(pthread_key_t *)key_ptr;
    for (zsize i = 0; i < g_keys->size; i++)
    {
        if(g_keys->thread_local_keys[i] == key)
            return pthread_setspecific(g_keys->thread_local_keys[i], data);
    } 
    return -1;
}