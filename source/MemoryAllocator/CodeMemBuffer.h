#pragma once

#include "dobby/common.h"
#include "MemoryAllocator.h"
struct MemBuffer {
  uint8_t *buffer;
  uint32_t buffer_size;
  uint32_t buffer_capacity;

  MemBuffer() {
    buffer = (uint8_t *)operator new(64);
    buffer_size = 0;
    buffer_capacity = 64;
  }

  ~MemBuffer() {
    operator delete((void *)buffer);
  }

  MemBlock dup() {
    uint8_t *copy_buf = (uint8_t *)operator new(buffer_size);
    memcpy(copy_buf, buffer, buffer_size);
    return MemBlock((addr_t)copy_buf, buffer_size);
  }

  uint8_t *data() {
    return buffer;
  }

  uint32_t size() {
    return buffer_size;
  }

  void read(uint32_t offset, void *out_buffer, int size) {
    memcpy(out_buffer, this->buffer + offset, size);
  }

  void write(uint32_t offset, void *in_buffer, int size) {
    memcpy(this->buffer + offset, in_buffer, size);
  }

  template <typename T> T read(int offset) {
    T value;
    read(offset, &value, sizeof(T));
    return value;
  }

  template <typename T> void write(int offset, T value) {
    write(offset, &value, sizeof(T));
  }

  void emit(void *in_buffer, int size) {
    ensure_capacity(size);
    write(buffer_size, in_buffer, size);
    buffer_size += size;
  }

  template <typename T> void emit(T value) {
    emit(&value, sizeof(value));
  }

  void ensure_capacity(int in_size) {
    if (buffer_size + in_size > buffer_capacity) {
      uint32_t new_capacity = buffer_capacity * 2;
      while (new_capacity < buffer_size + in_size) {
        new_capacity *= 2;
      }
      uint8_t *new_buffer = (uint8_t *)operator new(new_capacity);
      memcpy(new_buffer, buffer, buffer_size);
      operator delete(buffer);
      buffer = new_buffer;
      buffer_capacity = new_capacity;
    }
  }
};

struct CodeMemBuffer : MemBuffer {
  template <typename T> T Load(int offset) {
    return read<T>(offset);
  }

  template <typename T> void Store(int offset, T value) {
    write<T>(offset, value);
  }

  void EmitBuffer(uint8_t *buffer, uint32_t buffer_size) {
    emit(buffer, buffer_size);
  }

  template <typename T> void Emit(T value) {
    EmitBuffer((uint8_t *)&value, sizeof(value));
  }

#if defined(TARGET_ARCH_ARM)
  enum ExecuteState{ARMExecuteState, ThumbExecuteState};
  arm_inst_t LoadARMInst(uint32_t offset) {
    return *(arm_inst_t *)(data() + offset);
  }

  thumb1_inst_t LoadThumb1Inst(uint32_t offset) {
    return *(thumb1_inst_t *)(data() + offset);
  }

  thumb2_inst_t LoadThumb2Inst(uint32_t offset) {
    return *(thumb2_inst_t *)(data() + offset);
  }

  void RewriteAddr(uint32_t offset, addr32_t addr) {
    memcpy(data() + offset, &addr, sizeof(addr));
  }

  void RewriteARMInst(uint32_t offset, arm_inst_t instr) {
    *(arm_inst_t *)(data() + offset) = instr;
  }

  void RewriteThumb1Inst(uint32_t offset, thumb1_inst_t instr) {
    *(thumb1_inst_t *)(data() + offset) = instr;
  }

  void RewriteThumb2Inst(uint32_t offset, thumb2_inst_t instr) {
    memcpy(data() + offset, &instr, sizeof(instr));
  }

  void EmitARMInst(arm_inst_t instr) {
    Emit(instr);
  }

  void EmitThumb1Inst(thumb1_inst_t instr) {
    Emit(instr);
  }

  void EmitThumb2Inst(thumb2_inst_t instr) {
    Emit(instr);
  }
#elif defined(TARGET_ARCH_ARM64)
  typedef int32_t arm64_inst_t;
  arm64_inst_t LoadInst(uint32_t offset) {
    return *reinterpret_cast<int32_t *>(data() + offset);
  }

  void RewriteInst(uint32_t offset, arm64_inst_t instr) {
    *reinterpret_cast<arm64_inst_t *>(data() + offset) = instr;
  }
#elif defined(TARGET_ARCH_X86) || defined(TARGET_ARCH_X64)
  void FixBindLabel(int offset, int32_t disp) {
    Store(offset, disp);
  }
#endif
};
