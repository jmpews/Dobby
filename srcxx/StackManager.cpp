//
// Created by jmpews on 2018/6/14.
//

#include "StackManager.h"

ThreadStackManager::ThreadStackManager(ThreadLocalKey *key) {
    ThreadManager *threadManager = Singleton<ThreadManager>::GetInstance();
    threadManager->setThreadLocalData(key, static_cast<void *>(this));
}

ThreadStackManager *ThreadStackManager::initializeFromThreadLocalKey(ThreadLocalKey *key) {
    ThreadManager *threadManager    = Singleton<ThreadManager>::GetInstance();
    ThreadStackManager *threadStack = static_cast<ThreadStackManager *>(threadManager->getThreadLocalData(key));
    return threadStack;
}

void ThreadStackManager::pushCallStack(CallStackManager *call_stack) {
    call_stack->id           = call_stacks.size();
    call_stack->thread_stack = this;
    call_stacks.push_back(call_stack);
}

CallStackManager *ThreadStackManager::popCallStack() {
    CallStackManager *call_stack = call_stacks[call_stacks.size() - 1];
    call_stacks.pop_back();
    return call_stack;
}

void *CallStackManager::getCallStackValue(char *key) {
    std::map<char *, void *>::iterator it;
    it = kv_map.find(key);
    if (it != kv_map.end()) {
        return (void *)it->second;
    }
    return NULL;
}

void CallStackManager::setCallStackValue(char *key, void *value) {
    kv_map.insert(std::pair<char *, void *>(key, value));
}