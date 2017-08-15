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

SRC_SOURCES= $(wildcard src/*.c) $(wildcard src/platforms/darwin/*.c) $(wildcard src/platforms/arm64/*.c)
ZZDEPS_SOURCES = $(wildcard src/zzdeps/darwin/*.c) $(wildcard src/zzdeps/common/*.c) $(wildcard src/zzdeps/posix/*.c) 
ALL_SOURCES = $(SRC_SOURCES) $(ZZDEPS_SOURCES)

SRC_SOURCES_O = $(patsubst %.c,%.o, $(SRC_SOURCES))
ZZDEPS_SOURCES_O = $(patsubst %.c,%.o, $(ZZDEPS_SOURCES))
ALL_SOURCES_O = $(SRC_SOURCES_O) $(ZZDEPS_SOURCES_O)

OUTPUT_DIR = build

# capstone framework
CAPSTONE_INCLUDE = $(abspath deps/capstone/include)
CAPSTONE_LIB_DIR = $(abspath deps/capstone)
CAPSTONE_LIB = capstone.arm64

INCLUDE_DIR = -I$(CAPSTONE_INCLUDE)
LIB_DIR = -L$(CAPSTONE_LIB_DIR)
LIBS = -l$(CAPSTONE_LIB)

CFLAGS = -O0 -g
CXXFLAGS = $(CFLAGS) -stdlib=libc++ -std=c++11 -gmodules
LDFLAGS =  $(LIB_DIR) $(LIBS)

# OSX macOS
# http://hanjianwei.com/2013/01/27/abi-compatibility-between-c-plus-plus-11-and-c-plus-plus-98/
ZZ_GXX_BIN = `xcrun --sdk iphoneos --find clang++`
ZZ_GCC_BIN = `xcrun --sdk iphoneos --find clang`
ZZ_SDK = `xcrun --sdk iphoneos --show-sdk-path`
ZZ_GCC=$(ZZ_GCC_BIN) -isysroot $(ZZ_SDK) $(CFLAGS) $(INCLUDE_DIR) -arch arm64
ZZ_GXX=$(ZZ_GXX_BIN) -isysroot $(ZZ_SDK) $(CXXFLAGS) $(INCLUDE_DIR) -arch arm64

NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m

# ATTENTION !!!
# simple `ar` can't make a 'static library', need `ar -x` to extract `libcapstone.arm64.a` and then `ar rcs` to pack as `.a`
darwin.ios : $(ALL_SOURCES_O)
	@mkdir -p $(OUTPUT_DIR)
	@$(ZZ_GCC) -dynamiclib $(LDFLAGS) $(ALL_SOURCES_O) -o $(OUTPUT_DIR)/libhookzz.dylib
	@ar -rcs $(OUTPUT_DIR)/libhookzz.static.a $(SRC_SOURCES_O) $(CAPSTONE_LIB_DIR)/lib$(CAPSTONE_LIB).o/*.o
	@echo "$(OK_COLOR)build success for arm64(IOS)! $(NO_COLOR)"

$(SRC_SOURCES_O): %.o : %.c
	@$(ZZ_GCC) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

$(ZZDEPS_SOURCES_O): %.o : %.c
	@$(ZZ_GCC) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

# -undefined dynamic_lookup
test : darwin.ios
	@$(ZZ_GCC) -I/Users/jmpews/Desktop/SpiderZz/project/HookZz/include -c tests/test_hook_oc.m -o tests/test_hook_oc.o
	@$(ZZ_GCC) -dynamiclib -Wl,-U,_func -framework Foundation -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/build -lhookzz.static tests/test_hook_oc.o -o tests/test_hook_oc.dylib
	@echo "$(OK_COLOR)build [test_hook_oc.dylib] success for arm64(ios)! $(NO_COLOR)"

	@$(ZZ_GCC) -I/Users/jmpews/Desktop/SpiderZz/project/HookZz/include -c tests/test_hook_address.c -o tests/test_hook_address.o
	@$(ZZ_GCC) -dynamiclib -Wl,-U,_func -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/build -lhookzz.static tests/test_hook_address.o -o tests/test_hook_address.dylib
	@echo "$(OK_COLOR)build [test_hook_address.dylib] success for arm64(ios)! $(NO_COLOR)"

	@echo "$(OK_COLOR)build [test] success for arm64(IOS)! $(NO_COLOR)"

clean:
	@rm -rf $(ALL_SOURCES_O)
	@echo "$(OK_COLOR)clean all *.o success!$(NO_COLOR)"