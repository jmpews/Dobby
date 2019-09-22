#ifndef HOOKZZ_CUSTOM_CODE_H_
#define HOOKZZ_CUSTOM_CODE_H_

class CodeBuffer;

class AssemblerCodeBuffer : public CodeBuffer {
public:
  static AssemblerCodeBuffer *FinalizeTurboAssembler(AssemblerBase *assembler);
};

#endif