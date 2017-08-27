#include "thread-utils-posix.h"
#include <pthread.h>

ThreadLocalKeyList *g_thread_local_key_list = 0;


ThreadLocalKeyList *zz_posix_thread_new_thread_local_key_list() {
    ThreadLocalKeyList *keylist_tmp = (ThreadLocalKeyList *)malloc(sizeof(ThreadLocalKeyList));
    keylist_tmp->capacity = 4;
    keylist_tmp->keys = (ThreadLocalKey *)malloc(sizeof(ThreadLocalKey) * keylist_tmp->capacity);
    if(!keylist_tmp->keys) {
        return NULL;
    }
    keylist_tmp->size = 0;
    return keylist_tmp;
}

ThreadLocalKey *zz_posix_thread_new_thread_local_key(ThreadLocalKeyList *keylist) {
    if(!keylist)
        return NULL;

    if(keylist->size >= keylist->capacity) {
        ThreadLocalKey *keys_tmp = (ThreadLocalKey *)realloc(keylist->keys, sizeof(ThreadLocalKey) * keylist->capacity * 2);
        if(!keys_tmp)
            return NULL;
        keylist->keys = keys_tmp;
        keylist->capacity = keylist->capacity * 2;
    }
    return &(keylist->keys[keylist->size++]);
}

void zz_posix_thread_initialize_thread_local_key_list() {
    if(!g_thread_local_key_list) {
        g_thread_local_key_list = zz_posix_thread_new_thread_local_key_list();
    }
}

zpointer zz_posix_thread_new_thread_local_key_ptr() {
    if(!g_thread_local_key_list) {
        zz_posix_thread_initialize_thread_local_key_list();
    }

    ThreadLocalKey *key = zz_posix_thread_new_thread_local_key(g_thread_local_key_list);

    pthread_key_create(&key->key, NULL);
	return (zpointer)key;
}

zpointer zz_posix_thread_get_current_thread_data(zpointer key_ptr) {
    ThreadLocalKeyList *g_keys= g_thread_local_key_list;
    if(!key_ptr)
        return NULL;
    for (zsize i = 0; i < g_keys->size; i++)
    {
        if(&g_keys->keys[i] == key_ptr)
            return (zpointer)pthread_getspecific(g_keys->keys[i].key);
    }
    return NULL;
}

bool zz_posix_thread_set_current_thread_data(zpointer key_ptr, zpointer data) {
    ThreadLocalKeyList *g_keys= g_thread_local_key_list;
    
    for (zsize i = 0; i < g_keys->size; i++)
    {
        if(&g_keys->keys[i] == key_ptr)
            return pthread_setspecific(g_keys->keys[i].key, data);
    } 
    return false;
}

long zz_posix_get_current_thread_id() {
    return (long)pthread_self();
}