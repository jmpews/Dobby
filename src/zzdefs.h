//    Copyright 2017 jmpews
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.


#include <stdint.h> // for: uint64_t
/*
    -ARM64
    http://infocenter.arm.com/help/topic/com.arm.doc.den0024a/DEN0024A_v8_architecture_PG.pdf (7.2.1 Floating-point) (4.6.1 Floating-point register organization in AArch64)
    use struct and union to describe diagram in the above link, nice!

    -X86
    https://en.wikipedia.org/wiki/X86_calling_conventions
*/

#define GUM_INT5_MASK  0x0000001f
#define GUM_INT8_MASK  0x000000ff
#define GUM_INT10_MASK 0x000003ff
#define GUM_INT11_MASK 0x000007ff
#define GUM_INT12_MASK 0x00000fff
#define GUM_INT14_MASK 0x00003fff
#define GUM_INT16_MASK 0x0000ffff
#define GUM_INT18_MASK 0x0003ffff
#define GUM_INT19_MASK 0x0007ffff
#define GUM_INT24_MASK 0x00ffffff
#define GUM_INT26_MASK 0x03ffffff
#define GUM_INT28_MASK 0x0fffffff