//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_STACKMANAGER_H
#define HOOKZZ_STACKMANAGER_H

#include <map>

#include "hookzz.h"

#include "ThreadManager.h"

typedef struct _CallStackEntry {
    char *key;
    void *value;
} CallStackEntry;

class ThreadStackManager;

class CallStackManager {
  public:
    int id;
    class ThreadStackManager *thread_stack;
    zz_ptr_t retAddr;
    std::map<char *, void *> kv_map;

  public:
    void setCallStackValue(char *key, void *value);

    void *getCallStackValue(char *key);
};

class ThreadStackManager {
  public:
    int id;
    ThreadLocalKey *thread_local_key;
    std::vector<CallStackManager *> call_stacks;

  public:
    ThreadStackManager(ThreadLocalKey *key);

    static ThreadStackManager *initializeFromThreadLocalKey(ThreadLocalKey *key);

    void pushCallStack(CallStackManager *call_stack);

    CallStackManager *popCallStack();
};

#endif //HOOKZZ_STACKMANAGER_H
