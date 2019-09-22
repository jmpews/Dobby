class Heap {
public:
  HeapObject *AllocateRaw(int size);

private:
  Object *roots_;
  void *base;
};
