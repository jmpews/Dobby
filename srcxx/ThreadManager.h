//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_THREADMANAGER_H
#define HOOKZZ_THREADMANAGER_H

#include "CommonClass/DesignPattern/Singleton.h"

#include <iostream>
#include <vector>

typedef struct _ThreadLocalKey {
  pthread_key_t key;
} ThreadLocalKey;

class ThreadManager : public Singleton<ThreadManager> {
public:
  std::vector<ThreadLocalKey *> thread_local_keys;

public:
  ThreadLocalKey *allocateThreadLocalKey();
  void setThreadLocalData(ThreadLocalKey *thread_local_key, void *);
  void *getThreadLocalData(ThreadLocalKey *thread_local_key);
};

#endif //HOOKZZ_THREADMANAGER_H
