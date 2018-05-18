#include "thread-posix.h"

zz_ptr_t ThreadNewThreadLocalKeyPtr() { return zz_posix_thread_new_thread_local_key_ptr(); }

bool ThreadFreeThreadLocalKeyPtr(zz_ptr_t thread_local_key) {
    return zz_posix_thread_free_thread_local_key(thread_local_key);
}

zz_ptr_t ThreadGetThreadLocalValue(zz_ptr_t thread_local_key) {
    return zz_posix_thread_get_current_thread_data(thread_local_key);
}

bool ThreadSetThreadLocalValue(zz_ptr_t thread_local_key, zz_ptr_t data) {
    return zz_posix_thread_set_current_thread_data(thread_local_key, data);
}

long ThreadGetCurrentThreadID() { return zz_posix_get_current_thread_id(); }