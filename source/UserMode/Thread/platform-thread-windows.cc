#include "PlatformThread.h"

using namespace zz;

int OSThread::GetCurrentProcessId() {
}

int OSThread::GetCurrentThreadId() {
}

OSThread::LocalStorageKey OSThread::CreateThreadLocalKey() {
}

void OSThread::DeleteThreadLocalKey(LocalStorageKey key) {
}

void *OSThread::GetThreadLocal(LocalStorageKey key) {
}

void OSThread::SetThreadLocal(LocalStorageKey key, void *value) {
}
