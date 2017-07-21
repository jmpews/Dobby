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

SOURCES= $(wildcard src/*.c) $(wildcard src/platforms/darwin/*.c) $(wildcard src/platforms/arm64/*.c)
SOURCES_O = $(patsubst %.c,%.o, $(SOURCES))

OUTPUT_DIR = build

INCLUDE_DIR = -I$(abspath deps) -I$(abspath deps/capstone/include)
LIBS = -lcapstone.arm64
LIB_DIR = -L$(abspath deps/capstone)

CFLAGS = -O0 -g
LDFLAGS =  $(LIB_DIR) $(LIBS)

# OSX macOS
# http://hanjianwei.com/2013/01/27/abi-compatibility-between-c-plus-plus-11-and-c-plus-plus-98/
ZZ_GCC_BIN = `xcrun --sdk iphoneos --find clang`
ZZ_SDK = `xcrun --sdk iphoneos --show-sdk-path`
ZZ_GCC=$(ZZ_GCC_BIN) -isysroot $(ZZ_SDK) $(CFLAGS) $(INCLUDE_DIR)  -arch arm64 

NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m


darwin.ios : $(SOURCES_O)
	@$(ZZ_GCC) -dynamiclib $(LDFLAGS) $(SOURCES_O) -o hookzz.dylib
	@echo "$(OK_COLOR)build success for arm64(IOS)! $(NO_COLOR)"

$(SOURCES_O): %.o : %.c
	@$(ZZ_GCC) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"


test : $(SOURCES_O)

	@# test for parse self.
	@$(ZZ_GCC) -c tests/test_hook.c -o tests/test_hook.o
	@# -undefined dynamic_lookup
	@$(ZZ_GCC) -dynamiclib -Wl,-U,_func $(LDFLAGS) $(SOURCES_O) tests/test_hook.o -o tests/test_hook.dylib

	@# test for parse self, but it's dylib with `constructor`
	@#$(ZZ_GCC) -c tests/test_hook_objc_msgSend.c -o tests/test_hook_objc_msgSend.o
	@# -undefined dynamic_lookup
	@#$(ZZ_GCC) $(LDFLAGS) -Wl,-U,_objc_msgSend $(SOURCES_O) tests/test_hook_objc_msgSend.o -o tests/test_hook_objc_msgSend

	@$(ZZ_GCC) -framework Foundation -dynamiclib $(LDFLAGS) tests/test_ios.m -o tests/test_ios.dylib

	@echo "$(OK_COLOR)build [test] success for arm64(IOS)! $(NO_COLOR)"

clean:
	@rm -rf $(SOURCES_O)
	@echo "$(OK_COLOR)clean all *.o success!$(NO_COLOR)"