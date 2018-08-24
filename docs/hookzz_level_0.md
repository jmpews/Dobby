## what we need?

#### for memory
%%% runtime memory zone allocator

```c++
class ZoneObject {
	std::vector<Zone> GlobalVaiable;
	std::vector<Zone> ExecutableZone;
}
```

%%% executable memory slice allocator<br>
1. mmap allocate page-memory
2. search code cave

%%% patch code<br>
1. modify memory attribute as `rwx` (Android)
2. remap temp-page to dest-page
3. map temp-file to dest-page with force fixed flag

#### for instruction

%%% for disassembler:

1. how to decode `ldr_w`, `ldr_x`, `ldr_s`, `ldr_d`, `ldr_q` ?

%%% for assembler:

1. how to encode `ldr_w`, `ldr_x`, `ldr_s`, `ldr_d`, `ldr_q` ?
2. how to mov `uintptr_t` or `void *` value to a register?

%%% for instruction relocation