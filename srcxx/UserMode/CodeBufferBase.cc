
#include "UserMode/CodeBufferBase.h"

template <typename T> T CodeBufferBase::Load(int offset) { return *reinterpret_cast<T *>(buffer_ + offset); }

template <typename T> void CodeBufferBase::Store(int offset, T value) { *reinterpret_cast<T *>(buffer_ + offset) = value; }

template <typename T> void CodeBufferBase::Emit(T value) {
  // Ensure the free space enough for the template T value
  ensureCapacity(sizeof(T)+getSize());

  *reinterpret_cast<T *>(cursor_) = value;
  cursor_ += sizeof(T);
}
