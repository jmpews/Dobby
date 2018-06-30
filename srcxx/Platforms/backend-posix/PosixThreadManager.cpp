//
// Created by jmpews on 2018/6/14.
//

#include "PosixThreadManager.h"

#include "ThreadManager.h"

ThreadLocalKey *ThreadManager::allocateThreadLocalKey() {
    ThreadLocalKey *thread_local_key = new (ThreadLocalKey);
    thread_local_keys.push_back(thread_local_key);

    pthread_key_create(&thread_local_key->key, NULL);
    return thread_local_key;
}

void ThreadManager::setThreadLocalData(ThreadLocalKey *thread_local_key, void *data) {
    for (auto key : thread_local_keys) {
        if (key == thread_local_key) {
            pthread_setspecific(thread_local_key->key, data);
            return;
        }
    }
}

void *ThreadManager::getThreadLocalData(ThreadLocalKey *thread_local_key) {
    for (auto key : thread_local_keys) {
        if (key == thread_local_key) {
            return pthread_getspecific(thread_local_key->key);
        }
    }
    return NULL;
}