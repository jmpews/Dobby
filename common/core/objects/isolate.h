class Isolate {
public:
  static Isolate *Current() {
    Isolate *isolate = reinterpret_cast<Isolate *>(OSThread::GetExistingThreadLocal(isolate_key_));
    return isolate;
  }

  static void SetIsolateThreadLocals(Isolate *isolate);

  void *GetExecutableMemory(uword size);

private:
  Heap heap_;

  static OSThread::LocalStorageKey isolate_key_;
};
