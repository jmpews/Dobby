#### thumb instruct fixed scheme

```
# origin
adr r0, #0x2

# scheme-1-fixed [DO NOT USE]
mov.w r7, #offset
adr r0, #0x2
add.w r0, r0, r7

# scheme-2-fixed [USE THIS]
0x4: ldr.w R0, [pc, #0x0]
0x8: b.w 0x2
0xc: .long 0
```