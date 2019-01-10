#ifndef BASE_CODE_BUFFER_H_
#define BASE_CODE_BUFFER_H_

namespace zz {

#if TARGET_ARCH_ARM64 || TARGET_ARCH_ARM

class CodeBuffer : AutoBufferBase {

public:
  CodeBuffer(int capacity = 64) : AutoBufferBase(capacity) {}

  int32_t Load32(intptr_t position) { return *reinterpret_cast<int32_t *>(buffer_ + position); }

  template <typename T> T Load(intptr_t position) { return *reinterpret_cast<T *>(buffer_ + position); }

  void Store32(intptr_t position, int32_t value) { *reinterpret_cast<int32_t *>(buffer_ + position) = value; }

  template <typename T> void Store(intptr_t position, T value) { *reinterpret_cast<T *>(buffer_ + position) = value; }

  void Emit(int32_t inst) {
    Ensure(sizeof(int32_t));
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  void Emit64(int64_t inst) {
    Ensure(sizeof(int64_t));
    memcpy(cursor_, &inst, sizeof(inst));
    cursor_ += sizeof(inst);
  }

  template <typename T> void Emit(T value) {
    Ensure(sizeof(T));
    *reinterpret_cast<T *>(cursor_) = value;
    cursor_ += sizeof(T);
  }

  void EmitObject(const Object *object) {}
};

#elif TARGET_ARCH_IA32 || TARGET_ARCH_X64

class CodeBuffer : AutoBufferBase {

public:
  CodeBuffer(int capacity = 64) : AutoBufferBase(capacity) {}
};

#else
#error "unsupported architecture"
#endif

} // namespace zz

#endif
