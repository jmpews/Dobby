#include "thread-posix.h"

zz_ptr_t ZzThreadNewThreadLocalKeyPtr() { return zz_posix_thread_new_thread_local_key_ptr(); }

bool ZzThreadFreeThreadLocalKeyPtr(zz_ptr_t key_ptr) { return zz_posix_thread_free_thread_local_key(key_ptr); }

zz_ptr_t ZzThreadGetCurrentThreadData(zz_ptr_t key_ptr) { return zz_posix_thread_get_current_thread_data(key_ptr); }

bool ZzThreadSetCurrentThreadData(zz_ptr_t key_ptr, zz_ptr_t data) {
    return zz_posix_thread_set_current_thread_data(key_ptr, data);
}

long ZzThreadGetCurrentThreadID() { return zz_posix_get_current_thread_id(); }