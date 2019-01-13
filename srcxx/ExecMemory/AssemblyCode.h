#ifndef HOOKZZ_ASSEMBLY_CODE_H_
#define HOOKZZ_ASSEMBLY_CODE_H_

namespace zz {

class AssemblyCode : public LiteObject {

public:
  void initWithCodeBuffer(CodeBuffer *codeBuffer);

  void initWithAddressRange(void *address, int length);

  // dummy
  static Code *FinalizeCode(uintptr_t address, int size);

  // realize the buffer address to runtime code, and create a corresponding Code Object
  static Code *FinalizeFromAddress(uintptr_t address, int size);

  // =====

  // dummy method
  inline uintptr_t raw_instruction_start() { return (uintptr_t)instructions_; };

  // dummy method
  inline int raw_instruction_size() { return instruction_size_; };

private:
  uint8_t *instructions_;
  uword instruction_size_;
};

} // namespace zz

#endif
