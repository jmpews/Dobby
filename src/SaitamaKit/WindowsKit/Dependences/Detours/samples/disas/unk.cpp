/////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (x86.asm of disas.exe)
//
//  Microsoft Research Detours Package, Version 3.0.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

static int value = 0;

extern "C" void TestCodes()
{
    value++;
}
