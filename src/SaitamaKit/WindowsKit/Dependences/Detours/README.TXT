Microsoft Research Detours Package
Detours Version 3.0 Build_343

DISCLAIMER AND LICENSE:
=======================
The entire Detours package is covered by copyright law.
Copyright (c) Microsoft Corporation.  All rights reserved.
Portions are covered by patents owned by Microsoft Corporation.

Usage of the Detours package is covered under the End User License Agreement.
Your usage of Detours implies your acceptance of the End User License Agreement.

Detours 3.0 Professional, which includes rights to use Detours in commerical
products and production use is available through the online Microsoft Store:
http://www.microsoftstore.com/store/msstore/en_US/pd/productID.216531800


1. INTRODUCTION:
================
This document describes the installation and usage of this version of the
Detours package.  In particular, it provides an updated API table.

Complete documentation for the Detours package, including a detailed API
reference can be found in the Detours.chm file.


2. BUILD INSTRUCTIONS:
======================
If you installed Detours under the "Program Files" directory, copy the entire
contents of the detours directory to some other location where your account
has write access before attempting to build.

To build the libraries and the sample applications, type "nmake" in the
root directory of your Detours distribution.

If you are using Detours for the first time, a good practice is to start
by modifying one of the samples that is closest to your desired usage.


3. VERIFYING THE INSTALL AND BUILD:
===================================
After building the libraries and sample applications, you can verify that
the Detours packet works on your Windows OS by typing "nmake test" in the
samples\slept directory.  The output of "namke test" should be similar
to that contained in the file samples\slept\NORMAL.TXT.


4. CHANGES IN VERSION 3.0:
==========================
The following major changes were made in Detours 3.0 from Detours 2.x:
 * Support for scenarios that mix both 32-bit and 64-bit processes.
 * Support for ARM processors (in addition to support for X86, X64, and IA64).
 * Removal of the detoured.dll marker binary.
 * Compatibility improvements, especially on x64 processors.
 * Addition of APIs to enumerate PE binary Imports and to determine the
   module referenced by a function pointer.
 * Improved support for highly-optimized code on X64 processors.
 * Improved support for detouring hot-patchable binaries.
 * Improved algorithm for allocation of trampolines.


4.1. SUPPORT FOR MIXING 32-BIT AND 64-BIT PROCESSES:
====================================================
Previous version of Detours only supported pure 64-bit or pure 32-bit
environments.  Detours 3.0 includes support for creating parallel 32-bit
and 64-bit DLLs that can be loaded dynamically into target processes with
Detours automatically selecting the correct architectur DLL. The
DetourCreateProcessWithDllEx function selects the correct DLL based on
the word size (32-bit or 64-bit) of the target process.  For more
information see the "Detouring 32-bit and 64-bit Processes" section of
the Detours documentation (Detours.chm).


4.2. ARM SUPPORT:
=================
Detours 3.0 includes support for detouring functions on ARM processors
using the Thumb-2 instruction set.


4.3. REMOVAL OF DETOURED.DLL:
=============================
Products shipping with Detours 3.0 no longer need to include detoured.dll
in their dependencies.  Prior to Detours 3.0, Detours loaded the detoured.dll
shared library stub into any process which was modified by the insertion of
a detour.  This allowed the Microsoft Customer Support Services (CSS) and the
Microsoft Online Crash Analysis (OCA) teams to quickly and accurately
determine that the behavior of a process has been altered by a detour.
Microsoft does not provide customer assistance on detoured products.

With Detours 3.0, detoured.dll has been removed.  Advances in recent versions
of Windows allow CSS and OCA to accurately track third-party code that has
been loaded into a process, thus removing the need for detoured.dll.  One
side effect of this change is that the path to the detoured.dll is no longer
provided as an argument to DetourCreateProcessWithDll, reducing it's argument
count by one.


4.4. COMPATIBILITY IMPROVEMENTS:
================================
Fixes have been made in Detours 3.0 to improve support for target binaries
containing no DLL imports, DLL binaries compiled for online-patching,
binaries generated with hot-patching support, and 64-bit PE binaries
containing managed code.


4.5. APIS TO ENUMERATE PE BINARY IMPORTS:
=========================================
Added DetourEnumerateImports API to enumerate the functions imported by a
EXE or DLL.  Given a pointer to a function, the DetourGetContainingModule
API will return the HMODULE of the binary within which it resides.


4.6. TRANSACTIONAL MODEL AND THREAD UPDATE:
===========================================
Typically, a developer uses the Detours package to detour a family of
functions.  Race conditions can be introduced into the detour code as the
target functions are detoured one by one.  Also, the developer typically
wants a error model in which all target functions are detoured entirely or
none of the target functions are detoured if a particular function can't be
detoured.  In previous version of Detours, programmers either ignored
these race and error conditions, or attempted to avoid them by carefully
timing the insertion and deletion of detours.

To simplify the development model, Detours 3.0 uses a transactional model for
attaching and detaching detours.  Your code should call DetourTransactionBegin
to begin a transaction, issue a group of DetourAttach or DetourDetach calls to
affect the desired target functions, call DetourUpdateThread to mark threads
which may be affected by the updates, and then call
DetourTransactionCommit to complete the operation.

When DetourTransactionCommit is called, Detours suspends all effected
threads (except the calling thread), insert or removes the detours as
specified, updates the program counter for any threads that were running
inside the affected functions, then resumes the affected threads. If an error
occurs during the transaction, or if DetourTransactioAbort is called, Detours
safely aborts all of the operations within the transaction. From the perspective
of all threads marks marked for update, the entire transaction is atomic,
either all threads and functions are modified, or none are modified.


4.7. 64-BIT SUPPORT:
====================
Detours includes support for 64-bit execution on X64 and IA64 processors.
Detours understands the new 64-bit instructions of the X64 and IA64 and can
detour 64-bit code when used in a 64-bit process.


4.8. ALLOCATION OF TRAMPOLINES:
===============================
To intercept calls, Detours copies the first few instructions of the target
function into a block of memory called a trampoline.  In previous versions
of Detours, trampolines were allocated a close as possible to the target
code.  In some cases, the trampoline memory would conflict with later
DLL loads in the same process.  This would hurt performance by causing
later DLLs to be dynamically rebased.  Detours 3.0 includes a new algorithm
for allocating trampolines.  The new algorithm attempts to place trampolines
roughly 1GB above or below the target code in the address space.


5. API SUMMARY:
===============

5.1. APIS FOR DETOURING TARGET FUNCTIONS:
=========================================
DetourTransactionBegin()    - Begin a new detour transaction.

DetourUpdateThread()        - Mark a thread that should be included in the
                              current detour transaction.

DetourAttach()              - Attach a detour to a target function as part
                              of the current detour transaction.

DetourAttachEx()            - Attach a detour to a target function and
                              retrieved additional detail about the ultimate
                              target as part of the current detour transaction.

DetourDetach()              - Detach a detour from a target function as part
                              of the current detour transaction.

DetourSetIgnoreTooSmall()   - Set the flag to determine if failure to detour
                              a target function that is too small for detouring
                              is sufficient error to cause abort of the current
                              detour transaction.

DetourTransactionAbort()    - Abort the current detour transaction.

DetourTransactionCommit()   - Attempt to commit the current detour transaction.

DetourTransactionCommitEx() - Attempt to commit the current transaction, if
                              transaction fails, retrieve error information.


5.2. APIS FOR FINDING TARGETS:
==============================
DetourFindFunction()        - Tries to retrieve a function pointer for a named
                              function through the dynamic linking export
                              tables for the named module and then, if that
                              fails, through debugging symbols if available.

DetourCodeFromPointer()     - Given a function pointer, returns a pointer to the
                              code implementing the function.  Skips over extra
                              code often inserted by linkers or compilers for
                              cross-DLL calls.


5.3. APIS FOR FINDING ACCESSING LOADED BINARIES AND PAYLOADS:
=============================================================
DetourEnumerateModules()    - Enumerates all of the PE binaries loaded into a
                              process.

DetourGetContainingModule() - Return the module containing a function.

DetourGetEntryPoint()       - Returns a pointer the entry point for a module.

DetourGetModuleSize()       - Returns the load size of a module.

DetourEnumerateExports()    - Enumerates all exports from a module.

DetourEnumerateImports()    - Enumerates all import dependencies of a module.

DetourFindPayload()         - Finds the address of the specified payload
                              within a module.

DetourFindPayloadEx()       - Finds the specified payload if it exists anywhere
                              in the process.

DetourGetSizeOfPayloads()   - Returns the size of all payloads within a
                              module.


5.4. APIS FOR MODIFYING BINARIES:
=================================
DetourBinaryOpen()          - Open a binary for in-memory update.

DetourBinaryEnumeratePayloads() - Enumerats all of the payloads in a binary.

DetourBinaryFindPayload()   - Finds a specific payload within a binary.

DetourBinarySetPayload()    - Attaches a payload to a binary.

DetourBinaryDeletePayload() - Removes a payload from a binary.

DetourBinaryPurgePayloads() - Removes all payloads from a binary.

DetourBinaryEditImports()   - Edits the import tables of a binary.

DetourBinaryResetImports()  - Removes all edits to the import tables of a
                              binary including any edits made by previous
                              programs using the Detours package.

DetourBinaryWrite()         - Writes the updated binary to a file.

DetourBinaryClose()         - Release the in-memory updates for a binary.

DetourBinaryBind()          - Binds the DLL imports for a named binary file.


5.5. APIS FOR INSERTING DLLS INTO PROCESSES:
============================================
DetourCreateProcessWithDll() - Creates a new process with the specified
                               DLL inserted into it.

DetourCreateProcessWithDllEx() - Creates a new process with a DLL inserted,
                                 selecting a 32-bit DLL for a 32-bit target
                                 process or a 64-bit DLL for a 64-bit target
                                 process.

DetourRestoreAfterWith()     - Restores the contents of the in memory import
                               table after a process was started with
                               DetourCreateProcessWithDll.

DetourIsHelperProcess()      - Determines if a DLL is being loaded by rundll32
                               in a helper process in order to make the
                               transition from a 32-bit process to a 64-bit
                               process or from a 64-bit process to a 32-bit
                               process.

DetourFinishHelperProcess()  - Completes the operations of a helper process.


6. COMPATIBILITY:
=================
All Detours functions are compatible with all versions of Microsoft Windows
Operating Systems with the supported service packs installed. This includes
Windows XP, Windows Server 2003, Windows Server 2003 R2, Windows Vista,
Windows Server 2008, Windows 7, Windows Server 2008 R2, and Windows 8.


7. MANIFEST:
============
The Detours package consists of the Detours library source code and a number
of sample programs.  Descriptions of the sample programs can be found in
the help file.


8. NOTES:
=========
When writing detour functions, it is imperative that the binary-calling
convention of the detour and trampoline functions match exactly the
binary-calling convention of the target function.

In a few cases, when the sizeof() a return value is smaller than sizeof(int),
C or C++ compilers will generate non-compatible binary-calling conventions by
not widening the return value to an int as is customary for small return values.
The result is a syntactically-identical, but not binary-compatible, detour
function.  In most cases, the problem can be fixed be having the detour function
return a value widened to a sizeof(int) type.  Developers are urged to exercise
caution, and should insure that correct code is generated by their C or C++
compiler for detour functions with small return values.

When attaching a DLL to a binary with Detours DLL import APIs, the DLL must
export one procedure with export ordinal 1.  The exported procedure is not
called by the application, but it used as the import target.

Detours requires a compiler compatible with Visual C++.NET or later.


9. BUG REPORTS:
===============
Please send detailed bug reports to detours@microsoft.com.  Submitted bug
reports may be used to fix bugs in future versions of the Detours package.
Please include the text "DETOURS BUG REPORT" in the subject line. Please
also include the first line of this README.TXT file containing the full
version description information.  The detours@microsoft.com email address
is not a product support line.
