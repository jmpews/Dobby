
#include "CodeBuffer.h"

template <typename T> T CodeBuffer::Load(int offset) { return *reinterpret_cast<T *>(buffer_ + offset); }

template <typename T> void CodeBuffer::Store(int offset, T value) { *reinterpret_cast<T *>(buffer_ + offset) = value; }

template <typename T> void CodeBuffer::Emit(T value) {
  Ensure(sizeof(T));
  *reinterpret_cast<T *>(cursor_) = value;
  cursor_ += sizeof(T);
}
