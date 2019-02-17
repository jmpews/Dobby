## Prologue

#### Trampoline

```
adrp x17, stub@PAGE
add x17, x17, stub@PAGEOFF
ldr x17, [x17, #0]
br x17
```

## Epilogue