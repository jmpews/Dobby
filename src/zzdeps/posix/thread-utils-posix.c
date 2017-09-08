#include "thread-utils-posix.h"
#include <pthread.h>

ThreadLocalKeyList *g_thread_local_key_list = 0;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;

ThreadLocalKeyList *zz_posix_thread_new_thread_local_key_list() {
    ThreadLocalKeyList *keylist_tmp = (ThreadLocalKeyList *) malloc(sizeof(ThreadLocalKeyList));
    keylist_tmp->capacity = 4;
    keylist_tmp->keys = (ThreadLocalKey **) malloc(sizeof(ThreadLocalKey *) * keylist_tmp->capacity);
    if (!keylist_tmp->keys) {
        return NULL;
    }
    keylist_tmp->size = 0;
    return keylist_tmp;
}

bool zz_posix_thread_add_thread_local_key(ThreadLocalKeyList *key_list, ThreadLocalKey *key) {
    if (!key_list)
        return false;

    if (key_list->size >= key_list->capacity) {
        ThreadLocalKey **keys_tmp = (ThreadLocalKey **) realloc(key_list->keys,
                                                                sizeof(ThreadLocalKey *) * key_list->capacity * 2);
        if (!keys_tmp)
            return false;
        key_list->keys = keys_tmp;
        key_list->capacity = key_list->capacity * 2;
    }
    key_list->keys[key_list->size++] = key;
    return true;
}

void zz_posix_thread_initialize_thread_local_key_list() {
    ThreadLocalKeyList *g_key_list;
    if (!g_thread_local_key_list) {
        g_key_list = zz_posix_thread_new_thread_local_key_list();
    }
    g_thread_local_key_list = g_key_list;
}

zpointer zz_posix_thread_new_thread_local_key_ptr() {
    ThreadLocalKeyList *g_key_list;
    pthread_mutex_lock(&g_state_lock);
    if (!g_thread_local_key_list) {
        zz_posix_thread_initialize_thread_local_key_list();

    }
    g_key_list = g_thread_local_key_list;
    pthread_mutex_unlock(&g_state_lock);
    ThreadLocalKey *key = (ThreadLocalKey *) malloc(sizeof(ThreadLocalKey));
    zz_posix_thread_add_thread_local_key(g_key_list, key);

    pthread_key_create(&(key->key), NULL);
    return (zpointer) key;
}

zpointer zz_posix_thread_get_current_thread_data(zpointer key_ptr) {
    ThreadLocalKeyList *g_key_list = g_thread_local_key_list;
    if (!key_ptr)
        return NULL;
    for (zsize i = 0; i < g_key_list->size; i++) {
        if (g_key_list->keys[i] == key_ptr)
            return (zpointer) pthread_getspecific(g_key_list->keys[i]->key);
    }
    return NULL;
}

bool zz_posix_thread_set_current_thread_data(zpointer key_ptr, zpointer data) {
    ThreadLocalKeyList *g_key_list = g_thread_local_key_list;

    for (zsize i = 0; i < g_key_list->size; i++) {
        if (g_key_list->keys[i] == key_ptr)
            return pthread_setspecific(g_key_list->keys[i]->key, data);
    }
    return false;
}

long zz_posix_get_current_thread_id() {
    return (long) pthread_self();
}
