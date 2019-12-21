#ifndef ASSEMBLER_CODE_BUFFER_H
#define ASSEMBLER_CODE_BUFFER_H

class CodeBuffer;

class AssemblerCodeBuffer : public CodeBuffer {
public:
  static AssemblerCodeBuffer *FinalizeTurboAssembler(AssemblerBase *assembler);
};

#endif