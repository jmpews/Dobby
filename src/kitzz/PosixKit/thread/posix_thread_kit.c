#include "PosixKit/thread/posix_thread_kit.h"
#include <pthread.h>

ThreadLocalKeyList *g_thread_local_key_list = 0;

ThreadLocalKeyList *zz_posix_thread_new_thread_local_key_list() {
    ThreadLocalKeyList *keylist_tmp = (ThreadLocalKeyList *)malloc(sizeof(ThreadLocalKeyList));
    keylist_tmp->capacity           = 4;
    keylist_tmp->keys               = (ThreadLocalKey **)malloc(sizeof(ThreadLocalKey *) * keylist_tmp->capacity);
    if (!keylist_tmp->keys) {
        return NULL;
    }
    keylist_tmp->size = 0;
    return keylist_tmp;
}

bool zz_posix_thread_add_thread_local_key(ThreadLocalKeyList *keylist, ThreadLocalKey *key) {
    if (!keylist)
        return FALSE;

    if (keylist->size >= keylist->capacity) {
        ThreadLocalKey **keys_tmp =
            (ThreadLocalKey **)realloc(keylist->keys, sizeof(ThreadLocalKey *) * keylist->capacity * 2);
        if (!keys_tmp)
            return FALSE;
        keylist->keys     = keys_tmp;
        keylist->capacity = keylist->capacity * 2;
    }
    keylist->keys[keylist->size++] = key;
    return TRUE;
}

bool zz_posix_thread_free_thread_local_key(zz_ptr_t key_ptr) {
    ThreadLocalKeyList *g_keys = g_thread_local_key_list;
    zz_size_t i;

    if (!key_ptr)
        return NULL;
    for (i = 0; i < g_keys->size; i++) {
        if (g_keys->keys[i] == key_ptr) {
            g_keys->keys[i] = g_keys->keys[g_keys->size - 1];
        }
    }
    g_keys->size--;
    return TRUE;
}

void zz_posix_thread_initialize_thread_local_key_list() {
    if (!g_thread_local_key_list) {
        g_thread_local_key_list = zz_posix_thread_new_thread_local_key_list();
    }
}

zz_ptr_t zz_posix_thread_new_thread_local_key_ptr() {
    if (!g_thread_local_key_list) {
        zz_posix_thread_initialize_thread_local_key_list();
    }
    ThreadLocalKey *key = (ThreadLocalKey *)malloc(sizeof(ThreadLocalKey));
    zz_posix_thread_add_thread_local_key(g_thread_local_key_list, key);

    pthread_key_create(&(key->key), NULL);
    return (zz_ptr_t)key;
}

zz_ptr_t zz_posix_thread_get_current_thread_data(zz_ptr_t key_ptr) {
    ThreadLocalKeyList *g_keys = g_thread_local_key_list;
    zz_size_t i;

    if (!key_ptr)
        return NULL;
    for (i = 0; i < g_keys->size; i++) {
        if (g_keys->keys[i] == key_ptr)
            return (zz_ptr_t)pthread_getspecific(g_keys->keys[i]->key);
    }
    return NULL;
}

bool zz_posix_thread_set_current_thread_data(zz_ptr_t key_ptr, zz_ptr_t data) {
    ThreadLocalKeyList *g_keys = g_thread_local_key_list;
    zz_size_t i;

    for (i = 0; i < g_keys->size; i++) {
        if (g_keys->keys[i] == key_ptr)
            return pthread_setspecific(g_keys->keys[i]->key, data);
    }
    return FALSE;
}

long zz_posix_get_current_thread_id() { return (long)pthread_self(); }
