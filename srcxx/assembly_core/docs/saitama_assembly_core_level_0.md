#### SaitamaAssemblyCore for ?

* [Basic]     Assembler for encode
* [Basic]     Disassembler for decode
* [level_1]   Assembly Code Relocation
* [level_1]   Assembly CodeGen for JIT
* [level_1]   Assembly Interpreter
* [level_1]   Assembly Emulator

#### for memory

* allocate object
* allocate page
* allocate executable memory

#### for instruciton 

for load `void *` or `uintptr` value to register

* store `void *` or `uintptr` value as object, and load from the address of object.

#### for assembler

simple

#### for codegen

simple with assembler

#### for instrument

1. determined which instruction needed to relocated fix
2. need assembler
3. need codegen

#### for emulator