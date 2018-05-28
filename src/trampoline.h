/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef trampoline_h
#define trampoline_h

#include "hookzz.h"
#include "zkit.h"

#include "interceptor.h"

void TrampolineFree(HookEntry *entry);

void TrampolinePrepare(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildAll(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineActivate(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForEnter(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForEnterOnly(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForEnterTransfer(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForInstructionLeave(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForInvoke(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForLeave(struct _InterceptorBackend *self, HookEntry *entry);

void TrampolineBuildForDynamicBinaryInstrumentation(struct _InterceptorBackend *self, HookEntry *entry);

#ifdef TARGET_IS_IOS
// RetStatus ZzActivateSolidifyTrampoline(HookEntry *entry, zz_addr_t target_fileoff);
#endif

#endif