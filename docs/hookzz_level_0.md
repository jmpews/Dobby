## what we need?

#### for memory
1. runtime memory zone allocator

```c++
class ZoneObject {

}
```

2. executable memory slice allocator

#### for instruction

for disassembler:

1. how to decode `ldr_w`, `ldr_x`, `ldr_s`, `ldr_d`, `ldr_q` ?

for assembler:

1. how to encode `ldr_w`, `ldr_x`, `ldr_s`, `ldr_d`, `ldr_q` ?
2. how to mov `uintptr_t` or `void *` value to a register?