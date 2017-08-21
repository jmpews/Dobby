# HookZz docs

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)


# Export 5 core function

#### 1. `ZzInitialize`

initialize the interceptor and so on.

```
ZZSTATUS ZzInitialize(void);
```

#### 2. `ZzBuildHook`

build hook with `replace_call`, `pre_call`, `post_call`, but not enable. the definition of `PRECALL` and `POSTCALL` type is below.

```
@target_ptr: hook function address
@replace_ptr: replace function address
@origin_ptr: origin function address work with @replace_tpr
@pre_call_ptr: pre function call address
@post_call_ptr: post funciton call address

ZZSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_ptr, zpointer *origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr);
```

#### 3. `ZzBuildHookAddress`

build hook address(a piece of code) with `pre_call`, `half_call`. the definition of `PRECALL` and `POSTCALL` type is below.

```
@target_start_ptr: hook instruction start address
@target_end_ptr: hook instruction end address
@pre_call_ptr: pre function call address
@half_call_ptr: half function call address

ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, PRECALL pre_call_ptr, HALFCALL half_call_ptr);
```

#### 4. `ZzEnableHook`

enable hook with `code patch` at target_ptr.

```
@target_ptr: target address

ZZSTATUS ZzEnableHook(zpointer target_ptr);
```

#### 5. `ZzRuntimeCodePatch`

runtime code patch without codesign limit, and will work better with [MachoParser](https://github.com/jmpews/MachoParser).

```
@address: patch address
@codedata: code patch data
@codedata: code ptach data size

ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size);
```

# Export 3 core type:


#### 1. `PRECALL`, `POSTCALL`, `HALFCALL`

**For `RegState`:**

without the explicit argument, use `RegState` to replace, you can access all the registers at the moment. 

**For `ZzCallerStack`:**

if you want `pre_call` and `post_call`(`half_call`) as in the function, to access  trick variable like the `self`, you need `ZzCallerStack *stack`.

```
typedef void (*PRECALL)(RegState *rs, ZzCallerStack *stack);
typedef void (*POSTCALL)(RegState *rs, ZzCallerStack *stack);
typedef void (*HALFCALL)(RegState *rs, ZzCallerStack *stack);
```

#### 2. `RegState`

current all cpu register state, read `zzdefs.h` for detail.

```
typedef union FPReg_ {
    __int128_t q;
    struct {
        double d1; // Holds the double (LSB).
        double d2;
    } d;
    struct {
        float f1; // Holds the float (LSB).
        float f2;
        float f3;
        float f4;
    } f;
} FPReg;

typedef struct _RegState {
    uint64_t pc;
    uint64_t sp;

    union {
        uint64_t x[29];
        struct {
            uint64_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28;
        } regs;
    } general;

    uint64_t fp;
    uint64_t lr;

    union {
        FPReg q[8];
        FPReg q0,q1,q2,q3,q4,q5,q6,q7;
    } floating;
} RegState;
```

#### 3. `ZzCallerStack`

need the follow method to access the stack.

```
zpointer ZzCallerStackGet(ZzCallerStack *stack , char *key);
ZZSTATUS ZzCallerStackSet(ZzCallerStack *stack, char *key, zpointer value_ptr, zsize value_size);

#define STACK_GET(stack, key, type) *(type *)ZzCallerStackGet(stack, key)
#define STACK_SET(stack, key, value, type) ZzCallerStackSet(stack, key, &value, sizeof(type))
```
