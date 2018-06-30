#include "thread_local_storage.h"

#ifdef thread_local
thread_local void *_thread_variable;

void *get_thread_variable_value() { return _thread_variable; }

void set_thread_variable_value(void *value) { _thread_variable = value; }
#endif
