#    Copyright 2017 jmpews
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

SOURCES = AntiDebug.m

CFLAGS = -O0 -g

ZZ_GCC_BIN = `xcrun --sdk iphoneos --find clang`
ZZ_SDK = `xcrun --sdk iphoneos --show-sdk-path`
ZZ_GCC=$(ZZ_GCC_BIN) -isysroot $(ZZ_SDK) $(CFLAGS) $(INCLUDE_DIR)  -arch arm64 

NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m

#-Wl,-undefined,dynamic_lookup 
darwin.ios : $(SOURCES)
	@$(ZZ_GCC) -framework Foundation -dynamiclib AntiDebug.m -o AntiDebug.dylib
	@echo "$(OK_COLOR)build [test] success for arm64(IOS)! $(NO_COLOR)"