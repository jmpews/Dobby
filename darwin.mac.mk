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

SOURCES= $(wildcard src/*.c) $(wildcard src/platforms/darwin/*.c) $(wildcard src/platforms/x86/*.c)
SOURCES_O = $(patsubst %.c,%.o, $(SOURCES))
OUTPUT_DIR = build
INCLUDE_DIR = -I$(abspath deps) -I$(abspath deps/capstone/include)

LIB_DIR = -L$(abspath deps/capstone)
X64_LIB = -lcapstone.x86
LDFLAGS = $(LIB_DIR) $(X64_LIB)


X64_GCC_BIN = `xcrun --sdk macosx --find clang`
X64_SDK = `xcrun --sdk macosx --show-sdk-path`
CFLAGS = -O0 -g -Wall

# X64_GCC=$(X64_GCC_BIN) -isysroot $(X64_SDK) -dynamiclib $(CFLAGS) $(LDFLAGS) $(X64_LIB) -arch x86_64
X64_GCC = $(X64_GCC_BIN) -isysroot $(X64_SDK) $(CFLAGS) $(INCLUDE_DIR) -arch x86_64


darwinx86 : $(SOURCES_O)
	$(X64_GCC) -dynamiclib $(LDFLAGS) $(SOURCES_O) -o hookzz.dylib

$(SOURCES_O): %.o : %.c
	$(X64_GCC) -c $< -o $@

test : $(SOURCES_O)
	$(X64_GCC) -c tests/test_hook.c -o tests/test_hook.o
	$(X64_GCC) $(LDFLAGS) $(SOURCES_O) tests/test_hook.o -o tests/test_hook

	$(X64_GCC) -c tests/test_hook_objc_msgSend.c -o tests/test_hook_objc_msgSend.o
	$(X64_GCC) $(LDFLAGS) $(SOURCES_O) -undefined dynamic_lookup tests/test_hook_objc_msgSend.o -o tests/test_hook_objc_msgSend

clean:
	rm -rf $(SOURCES_O)

