//
// Created by z on 2018/6/14.
//

#ifndef HOOKZZ_INTERCEPTOR_H
#define HOOKZZ_INTERCEPTOR_H

#include "MemoryManager.h"
#include "ThreadManager.h"
#include "hookzz.h"

#include <iostream>
#include <vector>

typedef struct _FunctionBackup {
    void *address;
    int size;
    char data[32];
} FunctionBackup;

class Interceptor;
class InterceptorBackend;
struct HookEntryBackend;

typedef struct _HookEntry {
    void *target_address;

    HookType type;

    unsigned int id;

    bool isEnabled;

    bool isTryNearJump;

    bool isNearJump;

    PRECALL pre_call;
    POSTCALL post_call;
    STUBCALL stub_call;
    void *replace_call;

    void *on_enter_transfer_trampoline;
    void *on_enter_trampoline;
    void *on_invoke_trampoline;
    void *on_leave_trampoline;
    void *on_dynamic_binary_instrumentation_trampoline;

    FunctionBackup origin_prologue;

    struct HookEntryBackend *backend;

    Interceptor *interceptor;
} HookEntry;

class Interceptor {
  private:
    static int t;
    static Interceptor *priv_interceptor;
    MemoryManager *mm;

  public:
    bool isSupportRXMemory;
    std::vector<HookEntry *> hook_entries;

  public:
    static Interceptor *GETInstance();

    HookEntry *findHookEntry(void *target_address);

    void addHookEntry(HookEntry *hook_entry);

    void initializeBackend(MemoryManager *mm);

  private:
    Interceptor() {}
};

#endif //HOOKZZ_INTERCEPTOR_H
