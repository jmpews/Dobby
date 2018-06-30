#include "thread_local_storage.h"

#ifndef thread_local
#include <pthread.h>
static pthread_key_t _thread_variable_key = 0;

void *get_thread_variable_value() {
    if (!_thread_variable_key)
        return NULL;
    void *value = pthread_getspecific(_thread_variable_key);
    return value;
}

void set_thread_variable_value(void *value) {
    if (!_thread_variable_key) {
        int err = pthread_key_create(&_thread_variable_key, NULL);
        assert(err == 0);
    }
    int err = pthread_setspecific(flagKey, value);
    assert(err == 0);
}
#endif