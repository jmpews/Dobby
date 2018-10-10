#ifndef thread_local_storage_h
#define thread_local_storage_h

#include "core.h"
#include "hookzz.h"

void *get_thread_variable_value();

void set_thread_variable_value(void *value);
#endiff