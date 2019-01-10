#ifndef BASE_MEMORY_REGION_H_
#define BASE_MEMORY_REGION_H_

namespace zz {

class MemoryRegion {
public:
  MemoryRegion() : pointer_(NULL), size_(0) {}

  MemoryRegion(void *pointer, uword size) : pointer_(pointer), size_(size) {}

  void *pointer() const { return pointer_; }
  uword size() const { return size_; }
  void set_size(uword new_size) { size_ = new_size; }

  uword start() const { return reinterpret_cast<uword>(pointer_); }
  uword end() const { return start() + size_; }

  template <typename T> T Load(uword offset) const { return *ComputeInternalPointer<T>(offset); }

  template <typename T> void Store(uword offset, T value) const { *ComputeInternalPointer<T>(offset) = value; }

private:
  template <typename T> T *ComputeInternalPointer(uword offset) const {
    assert(size() >= sizeof(T));
    assert(offset <= size() - sizeof(T));
    return reinterpret_cast<T *>(start() + offset);
  }

  void *pointer_;
  uword size_;
};

} // namespace zz

#endif