#include "srcxx/AssemblyClosureTrampoline.h"

#include "assembly_core/modules/assembler/assembler-arm64.h"

ClosureTrampolineEntry *ClosureTrampoline::CreateClosureTrampoline() {

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
// use closure trampoline template code, find the executable memory and patch it.
#define CLOSURE_TRAMPOLINE_SIZE (7 * 4)

#else
// use assembler and codegen modules instead of template_code
#endif
}