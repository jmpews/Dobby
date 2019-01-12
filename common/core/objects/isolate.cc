OSThread::LocalStorageKey Isolate::isolate_key_ = 0;

void Isolate::SetIsolateThreadLocals(Isolate *isolate) { OSThread::SetThreadLocal(isolate_key_, isolate); }
